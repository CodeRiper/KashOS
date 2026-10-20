# Repository handoff instructions

- Read [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) for the long-term project
  requirements and [`docs/ROADMAP.md`](docs/ROADMAP.md) for current verified
  status and next work.
- Use [`docs/RESEARCH_SECURITY_MODELS.md`](docs/RESEARCH_SECURITY_MODELS.md)
  for the official-source comparison of the requested reference systems.
- Read [`docs/WORKLOG.md`](docs/WORKLOG.md) for the latest branch, completed
  work, verification limits, GitHub status, and next task.
- Start each change by checking the task evidence and the current source; old
  task statuses are not proof. Do not claim a feature is real unless its
  implementation and tests demonstrate it.
- Keep security-sensitive work small and isolated on a task branch. Add a
  regression check before fixing a discovered fake or unsafe behavior. Run the
  relevant host tests, kernel target check/build, and honesty gates.
- Save dated research sources and exact verification commands/results under
  `docs/EVIDENCE/`; update `docs/TASKS.md`, `docs/ROADMAP.md`, and this
  handoff when status changes.
- Do not claim seL4 proof parity, Qubes isolation, GrapheneOS parity, Linux app
  compatibility, Tor, HTTPS, TPM, or IOMMU support without direct evidence for
  the exact configuration.
- User environment requires shell commands to be prefixed with `rtk`.
