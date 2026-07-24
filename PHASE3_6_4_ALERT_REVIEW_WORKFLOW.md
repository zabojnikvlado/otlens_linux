# Phase 3.6.4 - Alert review workflow

The Central Alerts tab supports selecting one or more new alerts and applying a bulk operator verdict.

## Confirm selected

Confirm acknowledges the current alarm indication. The alert remains in history with status `confirmed`. It is not added to the accepted baseline. If the same condition occurs again, the sensor changes it back to `new` and raises the indication again.

## Approve selected

Approve marks the finding as expected behaviour. The alert ID is persisted with status `approved` and acts as a remembered accepted pattern. Repeated occurrences of that same deduplication ID are ignored and no longer increase the alert count or generate a new alert indication.

Approved state is included in the sensor persistence snapshot, so it survives sensor restart.

## Central UI

- Every new alert row has a checkbox.
- The table header contains a select-all checkbox.
- Selecting at least one row displays `Approve selected` and `Confirm selected` above the table.
- Bulk requests are automatically grouped by sensor and queued through the Central command queue.
