---
name: Release Checklist
about: Create a new release checklist. For maintainer use only.
title: 'Release Checklist: v0.0.0'
labels: task
assignees: k98kurz

---

## Release Checklist

<!-- For maintainer use only. If you are not a maintainer, do not use this template. -->

Once all other issues are complete, prepare to release the next version.

- [ ] Review and update docstrings
  - [ ] `classes.py`
  - [ ] `functions.py`
  - [ ] `tools.py`
- [ ] Update language_spec.md
- [ ] Update docs.md
- [ ] Update readme.md
- [ ] Update changelog.md
- [ ] Review and finalize documentation
- [ ] Ensure version strings are set to `'M.m.p'`
  - `version.py`
  - `pyproject.toml`
  - `readme.md` links
- [ ] Close milestone on GitHub
- [ ] Push tag and make release on GitHub
- [ ] Update PyPI
