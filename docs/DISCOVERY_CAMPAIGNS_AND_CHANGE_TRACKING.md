# Discovery campaigns and change tracking

Central now stores reusable discovery campaigns. A campaign keeps the selected sensor, targets, discovery profile, ports, rate limit, concurrency and timeout. Operators can run a saved campaign from the Reconnaissance tab without recreating the policy.

Each campaign run creates a normal reconnaissance job linked through `campaign_id`. Results are compared with the previous asset reconnaissance profile before the profile is updated. The generated change list records identity changes, operating-system or firmware changes, newly exposed services and removed services.

Every completed target result is also written to `asset_recon_history`. The Asset Detail → Recon history tab reads this durable history and displays the changes observed during each run. Existing reconnaissance jobs remain compatible; their `campaign_id` is empty and legacy results simply have no change list.

Database schema migration version 2 adds:

- `reconnaissance_campaigns`
- `reconnaissance_jobs.campaign_id`
- `asset_recon_history`
