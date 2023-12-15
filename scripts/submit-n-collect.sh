#!/usr/bin/env sh

set -e

DAP_TIMESTAMP=$((($(date +%s) / DAP_DURATION) * DAP_DURATION))

echo "running the submission job..."
${DAP_CLIENT}

echo "running the collection job..."
${DAP_COLLECTOR} --task-id "${DAP_TASK_ID}" --leader "${DAP_LEADER}" --authorization-bearer-token "${DAP_AUTH_BEARER_TOKEN}" \
  --vdaf "${DAP_VDAF}" ${DAP_VDAF_ARGS} --batch-interval-start "${DAP_TIMESTAMP}" --batch-interval-duration "${DAP_DURATION}" \
  --hpke-config "${DAP_HPKE_CONFIG}" --hpke-private-key "${DAP_HPKE_PRIVATE_KEY}"
