# Users & Roles view refresh fix

The Users & Roles page is a separate `users` view. Previously the view-scoped
refresh engine only loaded users and roles when the `settings` domain was due,
so opening the `users` tab rendered the tables before either `/v1/users` or
`/v1/roles` had been requested. PostgreSQL therefore contained the rows while
the browser showed empty tables.

The fix makes `users` a first-class refresh domain, invokes
`refreshUsersAndRoles()` when that domain is opened/refreshed, refreshes the
client-side table pager after replacing rows, and removes the stale permission
alias that treated `users` as `settings`. Management actions remain protected by
`users_roles_manage` on both the UI and API.
