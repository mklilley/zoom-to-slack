require('dotenv').config();

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3010);

// Capture the raw body as well as parsed JSON.
// Zoom signature verification uses the raw request body.
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);

const recentEvents = new Map();

function cleanupRecentEvents() {
  const now = Date.now();
  for (const [key, expiresAt] of recentEvents.entries()) {
    if (expiresAt <= now) recentEvents.delete(key);
  }
}

function seenRecently(key, ttlMs = 60_000) {
  cleanupRecentEvents();
  const now = Date.now();
  const expiresAt = recentEvents.get(key);
  if (expiresAt && expiresAt > now) return true;
  recentEvents.set(key, now + ttlMs);
  return false;
}

function timingSafeEqualStr(a, b) {
  const aBuf = Buffer.from(String(a), 'utf8');
  const bBuf = Buffer.from(String(b), 'utf8');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function signZoomMessage(message) {
  return crypto
    .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(message)
    .digest('hex');
}

function verifyZoomRequest(req) {
  const timestamp = req.get('x-zm-request-timestamp');
  const signature = req.get('x-zm-signature');

  if (!timestamp || !signature || !req.rawBody) {
    return false;
  }

  // Basic replay protection.
  const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 60 * 5) {
    return false;
  }

  const message = `v0:${timestamp}:${req.rawBody}`;
  const expectedSignature = `v0=${signZoomMessage(message)}`;

  return timingSafeEqualStr(expectedSignature, signature);
}

function buildValidationResponse(plainToken) {
  const encryptedToken = crypto
    .createHmac('sha256', process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(plainToken)
    .digest('hex');

  return {
    plainToken,
    encryptedToken,
  };
}

function extractJoinInfo(body) {
  const payload = body?.payload || {};
  const object = payload?.object || {};
  const participant = object?.participant || payload?.participant || {};

  const meetingId = object?.id ? String(object.id) : '';
  const meetingUuid = object?.uuid ? String(object.uuid) : '';
  const topic = object?.topic || '';
  const participantName =
    participant?.user_name ||
    participant?.email ||
    participant?.id ||
    'Someone';
  const participantEmail = participant?.email || '';
  const participantKey =
    participant?.user_id ||
    participant?.id ||
    participant?.email ||
    participant?.user_name ||
    'unknown';

  return {
    meetingId,
    meetingUuid,
    topic,
    participantName,
    participantEmail,
    participantKey: String(participantKey),
  };
}

async function postToSlack(payload) {
  const response = await fetch(process.env.SLACK_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Slack webhook failed: ${response.status} ${body}`);
  }
}


app.post('/', (req, res) => {
  if (!process.env.ZOOM_WEBHOOK_SECRET_TOKEN) {
    return res.status(500).json({ message: 'Missing ZOOM_WEBHOOK_SECRET_TOKEN' });
  }

  if (!verifyZoomRequest(req)) {
    return res.status(401).json({ message: 'Invalid Zoom signature' });
  }

  // Zoom URL validation challenge
  if (req.body?.event === 'endpoint.url_validation') {
    const plainToken = req.body?.payload?.plainToken;
    if (!plainToken) {
      return res.status(400).json({ message: 'Missing plainToken' });
    }

    return res.status(200).json(buildValidationResponse(plainToken));
  }

  const event = req.body?.event;

  if (
    event !== 'meeting.participant_joined' &&
    event !== 'meeting.participant_jbh_joined'
  ) {
    return res.sendStatus(204);
  }

  const info = extractJoinInfo(req.body);

  // Optional filter: only one recurring meeting
  if (
    process.env.ZOOM_MEETING_ID &&
    info.meetingId &&
    info.meetingId !== String(process.env.ZOOM_MEETING_ID)
  ) {
    return res.sendStatus(204);
  }

  // Suppress duplicate reconnect/join bursts
  const dedupeKey = `${info.meetingUuid || info.meetingId}:${info.participantKey}:${event}`;
  const dedupeWindowMs = Number(process.env.DEDUPE_WINDOW_MS || 60000);

  if (seenRecently(dedupeKey, dedupeWindowMs)) {
    return res.sendStatus(204);
  }

  // Acknowledge Zoom immediately, then notify Slack asynchronously.
  res.sendStatus(204);

  setImmediate(async () => {
    if (!process.env.SLACK_WEBHOOK_URL) {
      console.error('Missing SLACK_WEBHOOK_URL');
      return;
    }

    const payload = {
      text: `👋 ${info.participantName}'s here`,
    };


    try {
      await postToSlack(payload);
      console.log(
        `[ok] Forwarded ${event} for ${info.participantName} in meeting ${info.meetingId}`
      );
    } catch (err) {
      console.error('[error] Failed to post to Slack:', err);
    }
  });
});

app.listen(PORT, () => {
  console.log(`Zoom webhook server listening on port ${PORT}`);
  console.log(`Health check: GET /healthz`);
  console.log(`Webhook path: POST /zoom/webhook`);
});