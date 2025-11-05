# External Dependencies

This document tracks external dependencies to ensure stability and security.

## Frontend Dependencies

### Mermaid.js - Architecture Diagram Rendering

**Current Version**: 10.9.0
**Purpose**: Renders threat model architecture diagrams in the web UI
**CDN**: https://cdn.jsdelivr.net/npm/mermaid@10.9.0/dist/mermaid.min.js
**Fallback CDN**: https://unpkg.com/mermaid@10.9.0/dist/mermaid.min.js
**License**: MIT
**Last Updated**: 2025-01-05

**Why Locked?**
- Mermaid has breaking API changes between major versions
- v9 → v10 changed from `mermaid.run()` to `mermaid.render()`
- Locking to 10.9.0 ensures stability until we explicitly upgrade

**Upgrade Path**:
1. Test new version locally first
2. Check release notes: https://github.com/mermaid-js/mermaid/releases
3. Update version in `src/templates/index.html`
4. Update integrity hash (get from: https://www.srihash.org/)
5. Test threat model diagram rendering
6. Update this file

**Vendoring Option** (for fully offline deployment):
```bash
# Download mermaid.min.js locally
cd src/static/vendor
curl -o mermaid-10.9.0.min.js https://cdn.jsdelivr.net/npm/mermaid@10.9.0/dist/mermaid.min.js

# Update index.html to use local copy:
# <script src="/static/vendor/mermaid-10.9.0.min.js"></script>
```

## Backend Dependencies

### Python Packages

See `requirements.txt` for full list with locked versions.

**Critical Dependencies**:
- Flask 3.0.0 - Web framework
- Semgrep - SAST scanning
- Trivy - Dependency scanning
- GitLeaks - Secret detection

**Updating Python Dependencies**:
```bash
# Update specific package
pip install --upgrade <package>

# Regenerate lockfile
pip freeze > requirements.txt

# Test thoroughly before committing
```

## Dependency Security Policy

1. **Lock all versions** - Never use loose version constraints in production
2. **Use SRI hashes** - For CDN dependencies (prevents tampering)
3. **Fallback CDNs** - Multiple sources for critical dependencies
4. **Regular audits** - Review dependencies quarterly
5. **Security alerts** - Monitor GitHub Dependabot alerts
6. **Vendor critical** - Consider vendoring for air-gapped deployments

## Known Issues

### Mermaid.js
- **Issue**: API breaks between major versions (v9 → v10)
- **Mitigation**: Version locked to 10.9.0 with manual upgrade process
- **Timeline**: Review for v11 upgrade in Q2 2025

## Future-Proofing Recommendations

1. **Short-term** (done): Lock versions + SRI + fallback CDN ✅
2. **Medium-term** (optional): Vendor Mermaid.js locally for offline support
3. **Long-term** (consider):
   - Replace Mermaid with server-side rendering (D2, Graphviz)
   - Build custom SVG generator (no external dependencies)
   - Use WebAssembly version of Mermaid (better isolation)

## Maintenance Schedule

- **Monthly**: Check for security patches
- **Quarterly**: Review for feature upgrades
- **Annually**: Evaluate alternative libraries
- **On CVE**: Immediate security update

---

**Last Review**: 2025-01-05
**Next Review**: 2025-04-05
**Owner**: Security Team
