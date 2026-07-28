# Asset popup and discovery fix

## Asset popup

The Assets table had two independent row-click handlers. One opened the legacy vulnerability modal and the second opened the asset profile modal, resulting in two modal overlays. The row click is now handled once and opens only the asset profile. Action buttons and checkboxes remain isolated from the row action.

## Run safe discovery

The asset-detail action now:

- uses a self-contained safe-discovery policy rather than hidden values from the Reconnaissance form;
- prevents duplicate queued/running jobs for the same sensor and target;
- keeps the asset popup open and displays queued/running progress;
- polls job state and refreshes the asset profile when results arrive;
- reports when the sensor remains unavailable instead of silently navigating away.

The Central marks a reconnaissance job as `running` when the sensor pulls its command. Sensor results now contain a correctly populated `finished_at` timestamp.
