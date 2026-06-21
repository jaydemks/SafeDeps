# SafeDeps — Roadmap tecnica per portarlo da “prototipo promettente” a progetto da 8.5–9/10

Priority rule: do not add new features until CI, tests, threat model, docs and release gates are solid.

_Revisione preparata il 2026-06-17. Obiettivo: aumentare credibilità tecnica, ridurre bug potenziali, rendere il progetto leggibile, verificabile e competitivo contro benchmark esterni e progetti maturi._

## Stato avanzamento

Aggiornato al 2026-06-20:

- `v0.4.0` Beta Preview stabilization release: **99%**.
- Roadmap totale verso progetto da 9/10: **99%**.
- Test gate corrente: **324 test**, coverage reale **91.61%**, gate minimo **80%**.
- Focus corrente: sviluppo, test e review locale completati con gate WSL, fixture scan, smoke PowerShell/CMD nativo e smoke UI; restano Git/tag/release e validazione Trusted Publishing/attestations come blocco finale.

## 0. Diagnosi onesta

SafeDeps non va buttato. L’idea è buona: un firewall locale per impedire modifiche rischiose alle dipendenze prima che arrivino nel progetto.

Il problema non è l’idea. Il problema è che oggi il progetto sembra ancora in una fase dove “funziona in molti casi”, ma non dimostra abbastanza bene di funzionare in modo affidabile.

Le debolezze principali da correggere subito sono:

- test troppo concentrati e poco leggibili;
- CI troppo leggera rispetto al tipo di rischio che SafeDeps vuole controllare;
- npm e NuGet dichiarati come implementati ma ancora in validazione;
- tooling dev minimale;
- threat model non abbastanza esplicito;
- architettura da rendere più modulare e più simile a un framework di policy/verifier/package-manager adapter;
- documentazione più operativa che “fiduciaria”; manca una spiegazione forte di cosa SafeDeps garantisce e cosa non garantisce.

Fonti osservate:

- SafeDeps dichiara di essere più forte oggi su Python/pip, mentre npm e NuGet sono ancora in validazione/finalizzazione.
- SafeDeps ha solo `pytest` tra le dipendenze dev principali nel `pyproject.toml`.
- La CI attuale gira test su Python 3.10/3.11/3.12 in Ubuntu, ma non mostra ancora una matrice OS/shell/package-manager profonda.
- Il pre-commit attuale esegue essenzialmente lo scan SafeDeps stesso.
- Un benchmark esterno ha una struttura più modulare con package manager e verifiers separati, e una CI molto più aggressiva su versioni pip, npm e poetry.
- Datasette dimostra come appare un progetto maturo: molti test separati per area, tooling dev ricco, docs e workflow multipli.

## 1. Obiettivo di punteggio

| Area | Stato attuale stimato | Target dopo roadmap | Cosa serve per arrivarci |
|---|---:|---:|---|
| Idea/prodotto | 8.0 | 9.0 | Posizionamento chiaro: “policy gate preventivo per dependency changes e AI coding agents”. |
| Architettura | 6.5 | 8.8 | Adapter per ecosystem, verifier separati, core domain pulito, CLI sottile. |
| Test | 5.5 | 9.0 | Test piccoli per area, e2e reali, coverage gate, golden reports. |
| CI | 5.0 | 9.0 | Matrix OS + shell + Python + package manager. |
| Rischio bug | 6.0 | 8.7 | E2E su wrapper, runtime guard, project/global scope, bypass comuni. |
| Sicurezza percepita | 6.0 | 9.0 | Threat model, SECURITY.md, CodeQL, Scorecard, Dependency Review, release attestations. |
| Chiarezza per utenti | 6.5 | 8.8 | Quickstart breve, limitation matrix, messaggi di errore con fix, esempi reali. |
| Possibilità di successo | 8.0 | 9.0 | Stabilizzare prima di espandere, diventare affidabile su Python/pip, poi npm/NuGet. |

Regola fondamentale: **non aggiungere grandi feature prima di aver creato prove solide**. SafeDeps deve passare da “ho tante funzioni” a “posso dimostrare che le funzioni critiche reggono”.

## 2. P0 — Da fare subito, prima di qualsiasi altra feature

Stato operativo al 2026-06-18: il remote GitHub conferma `v0.3.4` come ultimo tag pubblicato. Il lavoro corrente è quindi promosso a `v0.4.0` Beta Preview stabilization release, con release note attiva in `RELEASE_NOTES_2026-06-18.md`.

### 2.1 Congelare la base attuale

Crea una branch dedicata:

```bash
git checkout -b stabilization/v0.4
```

Poi crea issue interne per ogni blocco di questa roadmap. Non lavorare tutto in un unico mega-commit.

Checklist:

- [x] Verificare il tag remoto più recente: ultimo tag pubblicato `v0.3.4`.
- [x] Avanzare la versione corrente a `0.4.0` perché il lavoro supera una patch release.
- [x] Creare `docs/KNOWN_LIMITATIONS.md`.
- [x] Creare `docs/THREAT_MODEL.md`.
- [x] Bloccare nuove feature non essenziali fino a quando `make checks` non esiste e non passa.
- [x] Scrivere nel README e nei docs che Python/pip è il percorso stabile, mentre npm/NuGet restano limitati/experimental finché la compatibility matrix non è verde.
- [x] Eseguire `scripts/release/preflight.py --expected-version 0.4.0`.
- [ ] Creare il tag finale `v0.4.0` solo dopo review, commit pulito e check finali.

Criterio “done”:

- la repo comunica onestamente cosa è stabile e cosa no;
- la branch di stabilizzazione esiste;
- ogni lavoro successivo è tracciato in issue piccole.

## 3. P0 — Spezzare e ricostruire la test suite

Questa è la priorità più importante. Un progetto security senza test leggibili non trasmette fiducia.

### 3.1 Nuova struttura consigliata

Sposta gradualmente i test in questa forma:

```text
tests/
  unit/
    test_policy_schema.py
    test_policy_decisions.py
    test_requirements_parser.py
    test_package_json_parser.py
    test_package_lock_parser.py
    test_nuget_parser.py
    test_lockfile_rules.py
    test_direct_urls.py
    test_git_urls.py
    test_vulnerability_feed.py
    test_baseline.py
    test_report_sarif.py
    test_report_cyclonedx.py
    test_report_spdx.py

  guard/
    test_guard_state.py
    test_guard_scope_project.py
    test_guard_scope_global.py
    test_runtime_guard_pip.py
    test_runtime_guard_python_m_pip.py
    test_shell_wrapper_posix.py
    test_shell_wrapper_powershell.py
    test_shell_wrapper_cmd.py
    test_cleanup.py
    test_activation.py

  integration/
    test_scan_python_project.py
    test_scan_node_project.py
    test_scan_dotnet_project.py
    test_scan_mixed_project.py
    test_precommit_hook.py
    test_doctor.py
    test_baseline_command.py
    test_approve_command.py
    test_explain_command.py

  e2e/
    test_pip_install_blocked.py
    test_pip_install_allowed.py
    test_python_m_pip_bypass_blocked.py
    test_npm_install_blocked.py
    test_dotnet_add_package_blocked.py

  ui/
    test_ui_scan_flow.py
    test_ui_guard_toggle.py
    test_ui_project_global_scope.py

  fixtures/
    python_basic/
    python_direct_url/
    node_basic/
    node_workspaces/
    dotnet_basic/
    mixed_monorepo/

  golden/
    sarif/
    cyclonedx/
    spdx/
    html/
```

### 3.2 Regole per i test

- Nessun file test sopra 400 righe, salvo eccezione motivata.
- Nessun test deve dipendere dalla rete.
- Ogni test deve usare `tmp_path` o fixture isolate.
- Ogni bug corretto deve aggiungere un regression test.
- I report SARIF/CycloneDX/SPDX devono avere golden snapshot.
- I wrapper shell devono essere testati come testo generato e come comportamento reale dove possibile.
- I test e2e devono essere pochi ma veri: creano un progetto temporaneo, attivano SafeDeps, tentano un comando reale, verificano blocco/allow.

### 3.3 Criteri minimi

Prima del prossimo release serio:

- [x] Coverage totale >= 80%.
- [x] Coverage su `policy`, `scanner`, `guard`, `reporters` >= 85%.
- [x] Test separati per Python/pip, npm, NuGet.
- [x] Test separati per PowerShell, CMD, Bash almeno a livello di wrapper generation.
- [x] Test reali per `pip install`, `python -m pip install`, `pip install -r requirements.txt`.
- [x] Golden tests per SARIF, CycloneDX, SPDX, HTML.

Target finale:

- coverage totale >= 90%;
- coverage sulle parti critiche >= 95%;
- test suite comprensibile in meno di 10 minuti da un maintainer esterno.

## 4. P0 — Aggiungere tooling dev serio

Oggi SafeDeps deve sembrare meno “script avanzato” e più “tool security professionale”.

### 4.1 Aggiorna `pyproject.toml`

Aggiungi almeno:

```toml
[project.optional-dependencies]
dev = [
  "pytest>=8.0",
  "pytest-cov>=5.0",
  "pytest-xdist>=3.0",
  "pytest-timeout>=2.0",
  "ruff>=0.9",
  "mypy>=1.10",
  "types-PyYAML",
  "build>=1.2",
  "twine>=5.0",
]
```

Poi aggiungi configurazioni minime:

```toml
[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM", "RUF"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q --strict-markers --strict-config --timeout=30"

[tool.coverage.run]
branch = true
source = ["safedeps"]

[tool.coverage.report]
fail_under = 80
show_missing = true
```

### 4.2 Aggiungi `Makefile`

```makefile
.PHONY: install-dev format format-check lint typecheck test coverage build smoke checks

install-dev:
	python -m pip install -e ".[dev]"

format:
	ruff format safedeps tests
	ruff check --fix safedeps tests

format-check:
	ruff format --check safedeps tests

lint:
	ruff check safedeps tests

# inizialmente permissivo; poi rendilo strict file per file
typecheck:
	mypy safedeps --ignore-missing-imports

test:
	pytest

coverage:
	pytest --cov=safedeps --cov-report=term-missing --cov-report=xml

build:
	python -m build
	twine check dist/*

smoke:
	python -m safedeps.cli --help
	python -m safedeps.cli explain FLOATING_VERSION

checks: format-check lint typecheck coverage build smoke
```

### 4.3 Aggiorna `.pre-commit-config.yaml`

Non usare solo SafeDeps dentro SafeDeps. Il pre-commit deve controllare anche qualità generale.

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.11.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: local
    hooks:
      - id: safedeps-scan
        name: safedeps scan
        entry: safedeps scan . --fail-on HIGH --out security-artifacts
        language: system
        pass_filenames: false
```

Criterio “done”:

- `make checks` passa localmente;
- lo stesso comando passa in CI;
- ogni PR futura deve passare `format-check`, `lint`, `typecheck`, `coverage`, `build`.

## 5. P0 — CI da progetto security, non da libreria piccola

La CI attuale è troppo leggera per un tool che intercetta installazioni. La parte fragile non è solo Python: sono OS, shell, venv, PATH, package manager e wrapper.

### 5.1 Workflow minimi

Crea questi workflow:

```text
.github/workflows/
  unit.yml
  integration.yml
  e2e-pip.yml
  e2e-npm.yml
  e2e-nuget.yml
  quality.yml
  security.yml
  release.yml
```

### 5.2 Matrix consigliata

`unit.yml`:

- OS: `ubuntu-latest`, `windows-latest`, `macos-latest`
- Python: `3.10`, `3.11`, `3.12`, `3.13`
- comando: `make checks`

`e2e-pip.yml`:

- OS: Ubuntu, Windows, macOS
- Python: 3.10–3.13
- pip: representative versions, ad esempio vecchia supportata, intermedia, latest
- casi:
  - `pip install six`
  - `pip install six==1.17.0`
  - `python -m pip install six`
  - `pip install -r requirements.txt`
  - install dentro venv
  - install fuori project scope

`e2e-npm.yml`:

- Node/npm: versioni rappresentative supportate
- OS: Ubuntu + Windows almeno
- casi:
  - `npm install lodash`
  - `npm install lodash@4.17.21`
  - `npm ci`
  - `package-lock.json` v2/v3
  - workspace semplice

`e2e-nuget.yml`:

- .NET SDK: LTS corrente + versione corrente stabile
- OS: Ubuntu + Windows
- casi:
  - `dotnet add package`
  - `PackageReference`
  - `Directory.Packages.props`
  - restore con lock file dove applicabile

### 5.3 Quality/security workflow

Aggiungi:

- CodeQL per vulnerabilità/errori nel codice;
- GitHub Dependency Review Action per bloccare dipendenze vulnerabili introdotte nelle PR;
- Dependabot per aggiornamenti di GitHub Actions e pip;
- OpenSSF Scorecard;
- upload SARIF generato da SafeDeps, quando presente;
- build wheel/sdist + `twine check`;
- release solo da tag.

Criterio “done”:

- PR bloccata se test, lint, typecheck, coverage o build falliscono;
- almeno un e2e reale per pip su tutti e tre gli OS;
- npm e NuGet non più dichiarati “supportati” finché la rispettiva e2e matrix non è verde.

## 6. P1 — Rifattorizzare l’architettura

Obiettivo: SafeDeps deve diventare modulare. Ogni ecosystem deve sembrare un plugin interno, non una serie di if dentro la CLI.

### 6.1 Nuovo modello interno

Crea oggetti core stabili:

```python
@dataclass(frozen=True)
class PackageTarget:
    manager: str
    name: str
    version: str | None
    source: str | None
    file: str | None
    requested_by: str | None = None

@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    manager: str
    package: str | None
    message: str
    file: str | None = None
    fix: str | None = None

@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    findings: tuple[Finding, ...]
    reason: str
```

### 6.2 Interfacce consigliate

```python
class PackageManagerAdapter(Protocol):
    name: str

    def detect_project(self, root: Path) -> bool: ...
    def parse_declared_dependencies(self, root: Path) -> list[PackageTarget]: ...
    def parse_lockfiles(self, root: Path) -> list[PackageTarget]: ...
    def inspect_install_command(self, argv: list[str]) -> list[PackageTarget]: ...

class Verifier(Protocol):
    name: str

    def verify(self, targets: list[PackageTarget], context: ScanContext) -> list[Finding]: ...

class Reporter(Protocol):
    format: str

    def write(self, result: ScanResult, output: Path) -> None: ...
```

### 6.3 Nuova struttura del package

```text
safedeps/
  cli/
    __init__.py
    main.py
    commands_scan.py
    commands_setup.py
    commands_doctor.py
    commands_baseline.py
    commands_explain.py

  core/
    models.py
    result.py
    severity.py
    errors.py
    filesystem.py

  policy/
    schema.py
    loader.py
    decisions.py
    approvals.py

  ecosystems/
    pip/
      adapter.py
      parser_requirements.py
      parser_lock.py
      command_inspector.py
    npm/
      adapter.py
      parser_package_json.py
      parser_lock.py
      command_inspector.py
    nuget/
      adapter.py
      parser_csproj.py
      parser_props.py
      command_inspector.py

  verifiers/
    base.py
    pinned_versions.py
    lockfiles.py
    direct_url.py
    osv.py
    malicious_dataset.py
    package_age.py
    publisher_churn.py
    typo_squat.py
    provenance.py

  guard/
    state.py
    setup.py
    scope.py
    runtime.py
    wrappers_posix.py
    wrappers_powershell.py
    wrappers_cmd.py
    cleanup.py

  reporters/
    json_report.py
    html_report.py
    sarif.py
    cyclonedx.py
    spdx.py

  ui/
    server.py
    assets/
```

### 6.4 Regole architetturali

- La CLI non deve contenere logica di security: solo parsing argomenti e orchestrazione.
- I parser non devono scrivere file.
- I verifier non devono modificare stato globale.
- I reporter non devono decidere severity.
- Il guard non deve conoscere i dettagli di SARIF/CycloneDX/SPDX.
- Tutto ciò che tocca filesystem/shell deve essere isolato e testato.
- Ogni ecosystem deve avere lo stesso contratto: detect → parse → inspect command → produce targets.

Criterio “done”:

- aggiungere un nuovo ecosystem richiede un adapter e test dedicati, non modifiche diffuse in 10 file;
- `safedeps.cli` è piccolo;
- i test unitari possono testare policy/verifier senza shell, venv o subprocess.

## 7. P1 — Threat model e documentazione security

Questa parte aumenta il punteggio più di molte feature. Un tool security serio dice chiaramente cosa protegge e cosa no.

### 7.1 Crea `docs/THREAT_MODEL.md`

Struttura consigliata:

```md
# SafeDeps Threat Model

## Goal
SafeDeps is a preventive dependency policy gate. It makes risky dependency changes harder to introduce by accident or by automated tools.

## Non-goals
SafeDeps does not prove that a package is safe. SafeDeps does not replace sandboxing, endpoint security, code review, pip-audit, osv-scanner, or registry-side malware detection.

## Protected assets
- project dependency manifests
- lockfiles
- developer workstation package manager commands
- CI dependency changes

## Trust boundaries
- local shell
- Python interpreter startup hook
- generated wrappers
- package registries
- local policy files
- CI environment

## Attack scenarios
| Scenario | Covered? | Notes |
|---|---|---|
| Unpinned dependency added by AI agent | Yes | Block when policy requires exact versions. |
| Known malicious package in local feed/OSV | Yes, if feed available | Depends on verifier data. |
| Direct URL package | Yes | Must be blocked or explicitly approved. |
| Git URL dependency | Yes | Must require commit pin or approval. |
| Dependency confusion | Partial | Needs private package policy. |
| Shell bypass | Partial | Runtime guard and e2e needed. |
| User disables guard | No | Must be visible in doctor/status. |
| Malicious maintainer release | Partial | Needs age/churn/provenance signals. |
```

### 7.2 Crea anche

```text
docs/POLICY.md
docs/BYPASS_AND_APPROVALS.md
docs/ECOSYSTEM_SUPPORT.md
docs/CI_INTEGRATION.md
docs/ARCHITECTURE.md
SECURITY.md
CONTRIBUTING.md
```

### 7.3 Frasi da evitare

Evita promesse tipo:

- “ensures dependencies are safe”;
- “protects from all malicious packages”;
- “unbreakable guard”;
- “AI-proof”.

Usa invece:

- “prevents unapproved dependency changes”;
- “enforces dependency policy before install/commit/CI”;
- “reduces accidental supply-chain risk”;
- “best-effort local guard with explicit limitations”.

Criterio “done”:

- un maintainer security capisce in 5 minuti garanzie, limiti e bypass;
- ogni feature dichiarata nel README è coperta da almeno un test o segnata come experimental.

## 8. P1 — Stabilizzare Python/pip prima di tutto

Python/pip deve diventare la punta di diamante. Non serve dire “supportiamo tutto” se pip non è blindato.

### 8.1 Casi pip da coprire

- [x] `pip install package`
- [x] `pip install package==x.y.z`
- [x] `python -m pip install package`
- [x] `pip install -r requirements.txt`
- [ ] `pip install -c constraints.txt -r requirements.txt`
- [ ] `pip install .`
- [ ] `pip install -e .`
- [ ] `pip install git+https://...`
- [ ] `pip install https://.../package.whl`
- [ ] `pip install ./local/path`
- [ ] `pip install --index-url ...`
- [ ] `pip install --extra-index-url ...`
- [x] install dentro venv
- [ ] install globale
- [x] project scope
- [ ] global scope
- [ ] auto guard on/off
- [x] cleanup guard
- [x] reinstall guard idempotente

### 8.2 Policy pip consigliate

- Blocca versioni floating se policy richiede pin.
- Blocca direct URL se non approvato.
- Blocca git URL se non pinned a commit hash.
- Blocca local path se non approvato.
- Avvisa su `--extra-index-url` perché può aprire dependency confusion.
- Richiedi lockfile se `require_lockfiles=true`.
- Supporta baseline con scadenza.
- Ogni allow manuale deve avere reason + expiry.

Criterio “done”:

- Python/pip non è più “strongest today” solo nel README: è dimostrato da test e2e su OS diversi.

## 9. P2 — npm: o diventa vero, o va marcato experimental

npm è importante, ma è pericoloso dichiararlo stabile senza matrice.

### 9.1 Casi npm minimi

- [x] `package.json` dependencies/devDependencies/optionalDependencies/peerDependencies
- [x] `package-lock.json` v2 e v3
- [x] `npm install package`
- [x] `npm install package@version`
- [x] `npm install`
- [x] `npm ci`
- [ ] workspace semplice
- [ ] alias package, es. `alias@npm:real-package`
- [ ] git dependency
- [ ] tarball URL
- [ ] local path
- [x] scoped packages, es. `@scope/pkg`
- [x] custom registry

### 9.2 Policy npm consigliate

- Bloccare `latest`, `*`, `^`, `~` se la policy richiede exact pin.
- Bloccare tarball URL se non approvato.
- Bloccare git dependency se non pinned a commit.
- Avvisare su package molto recente.
- Avvisare su maintainer/publisher churn.
- Riconoscere pacchetti scoped privati per evitare falsi positivi.

Criterio “done”:

- README passa da “implemented, still being validated” a “supported for these npm versions and commands”.
- Tutto ciò che non è coperto resta in `docs/ECOSYSTEM_SUPPORT.md` come unsupported.

## 10. P2 — NuGet/.NET: restringere il claim e testare bene

NuGet è un vantaggio competitivo solo se è vero. Altrimenti abbassa la fiducia.

### 10.1 Casi NuGet minimi

- [x] `.csproj` con `PackageReference`
- [x] `Directory.Packages.props`
- [x] `packages.config` se vuoi supporto legacy
- [x] `dotnet add package PackageName`
- [x] `dotnet add package PackageName --version x.y.z`
- [x] restore con lockfile dove previsto
- [x] package source custom
- [ ] package source privato
- [x] floating versions, es. `1.*`

### 10.2 Decisione consigliata

Dividi il supporto in due livelli:

| Livello | Significato |
|---|---|
| `scan-supported` | SafeDeps legge manifest/lockfile e segnala problemi. |
| `guard-supported` | SafeDeps blocca comandi runtime con test e2e. |
| `experimental` | Implementato ma non ancora affidabile. |

NuGet dovrebbe restare `scan-supported` o `experimental` finché `dotnet add package` non è testato in CI su Windows e Ubuntu.

Criterio “done”:

- nessun claim generico “NuGet supported” senza tabella precisa per comandi/file/versioni.

## 11. P2 — Verifier: qui SafeDeps può distinguersi

Per distinguersi non devi copiare tutto: devi avere verifier più chiari, componibili e documentati.

### 11.1 Verifier minimi

```text
verifiers/
  pinned_versions.py
  lockfiles.py
  direct_url.py
  git_url.py
  local_path.py
  osv.py
  local_vulnerability_feed.py
  package_age.py
  publisher_churn.py
  maintainer_change.py
  typo_squat.py
  dependency_confusion.py
  provenance.py
```

### 11.2 Ogni verifier deve avere

- nome stabile;
- descrizione breve;
- input richiesti;
- falsi positivi noti;
- severity default;
- policy options;
- test unitari;
- esempio di finding;
- remediation/fix suggerito.

Esempio finding buono:

```json
{
  "rule": "DIRECT_URL_DEPENDENCY",
  "severity": "HIGH",
  "manager": "pip",
  "package": "unknown",
  "file": "requirements.txt",
  "message": "Direct URL dependencies are blocked by policy.",
  "fix": "Pin to a trusted registry package or approve this URL with an expiry."
}
```

### 11.3 Verifier che aumentano davvero il valore

| Verifier | Valore |
|---|---|
| OSV | Copertura vulnerabilità nota. |
| Local malicious feed | Funziona offline e in enterprise. |
| Package age | Blocca pacchetti appena creati. |
| Maintainer/publisher churn | Segnale utile per takeover. |
| Direct URL/Git URL | Molto importante con AI coding agents. |
| Dependency confusion | Forte valore enterprise. |
| Provenance/attestations | Aumenta fiducia sulle release PyPI quando dati disponibili. |
| Private namespace policy | Riduce falsi positivi su package aziendali. |

Criterio “done”:

- ogni finding spiega “perché è un problema” e “come risolverlo”;
- ogni verifier è disattivabile/configurabile da policy;
- ogni verifier ha test offline.

## 12. P2 — Policy schema professionale

La policy deve sembrare un contratto stabile, non un JSON casuale.

### 12.1 Crea schema versionato

```text
safedeps/policy/schemas/safedeps.policy.v1.json
```

Campi consigliati:

```json
{
  "schema": "safedeps.policy.v1",
  "fail_on": "HIGH",
  "default_action": "warn",
  "require_exact_versions": true,
  "require_lockfiles": true,
  "allow_direct_urls": false,
  "allow_git_urls": false,
  "allow_local_paths": false,
  "allow_extra_index_url": false,
  "private_namespaces": {
    "pip": ["company-*"],
    "npm": ["@company/*"],
    "nuget": ["Company.*"]
  },
  "approvals": {
    "require_reason": true,
    "require_expiry": true,
    "max_expiry_days": 30
  },
  "verifiers": {
    "osv": {"enabled": true},
    "package_age": {"enabled": true, "min_age_days": 7},
    "publisher_churn": {"enabled": true}
  }
}
```

### 12.2 Criteri policy

- [x] Validazione schema.
- [x] Messaggio chiaro se policy non valida.
- [ ] Migrazione schema se in futuro cambia.
- [ ] `safedeps policy init`.
- [ ] `safedeps policy validate`.
- [ ] `safedeps policy explain`.

Criterio “done”:

- un team può mettere SafeDeps in CI senza leggere il codice.

## 13. P2 — Report e integrazioni

SafeDeps deve produrre output utili sia a umani sia a CI.

### 13.1 Output minimi

- `safedeps-report.json`
- `safedeps-report.html`
- SARIF 2.1.0
- CycloneDX JSON
- SPDX JSON
- exit code stabile:
  - `0`: allowed/no blocking findings
  - `1`: runtime/internal error
  - `2`: policy violation/blocking finding

### 13.2 Integrazioni

- GitHub Action ufficiale: `safedeps-action`.
- Pre-commit hook documentato.
- CI examples per GitHub Actions, GitLab CI, Azure Pipelines.
- Badge README: CI, PyPI, coverage, OpenSSF Scorecard, CodeQL.

### 13.3 Criterio “done”

- un utente può copiare 15 righe YAML e avere SafeDeps in CI;
- SARIF appare in GitHub Code Scanning;
- JSON output è stabile e documentato.

## 14. P2 — UX: farlo capire in 90 secondi

Il README deve diventare più corto sopra la piega. Ora deve vendere fiducia, non solo comandi.

### 14.1 Nuova apertura README consigliata

```md
# SafeDeps

SafeDeps is a local dependency policy firewall for developers, CI, and AI coding agents.

It blocks risky dependency changes before they are installed, committed, or merged.

Typical blocks:
- unpinned packages
- direct URL or Git URL dependencies
- missing lockfiles
- known vulnerable or malicious packages
- unapproved package-manager installs

SafeDeps does not prove that packages are safe. It enforces your dependency policy at the moment a risky change is introduced.
```

### 14.2 Sezioni README consigliate

1. What SafeDeps protects
2. Quickstart
3. Example block
4. Supported ecosystems table
5. CI usage
6. Policy example
7. Reports
8. Limitations
9. Comparison
10. Security model

### 14.3 Supported ecosystems table

```md
| Ecosystem | Scan | Runtime guard | CI | Status |
|---|---|---|---|---|
| Python/pip | Yes | Yes | Yes | Stable |
| npm | Yes | Partial | Yes | Experimental until e2e matrix is green |
| NuGet/.NET | Yes | Partial | Yes | Experimental until e2e matrix is green |
```

Criterio “done”:

- README non contiene promesse non provate;
- l’utente capisce subito cosa installare, cosa succede, cosa non è supportato.

## 15. P3 — Release engineering e supply-chain credibility

Un tool security deve essere distribuito in modo più sicuro della media.

### 15.1 Release workflow

- release solo da tag `vX.Y.Z`;
- build wheel/sdist in CI;
- `twine check`;
- pubblicazione PyPI con Trusted Publishing;
- attestations PyPI quando disponibili tramite workflow supportato;
- changelog generato o mantenuto manualmente;
- SBOM allegato alla release;
- GitHub release notes con breaking changes e migration guide.

### 15.2 File da aggiungere

```text
CHANGELOG.md
SECURITY.md
CONTRIBUTING.md
.github/dependabot.yml
.github/workflows/release.yml
.github/workflows/codeql.yml
.github/workflows/scorecard.yml
.github/workflows/dependency-review.yml
```

### 15.3 Criterio “done”

- nessun token PyPI lungo in GitHub Secrets;
- ogni release è riproducibile dal tag;
- wheel e sdist sono controllati prima dell’upload;
- OpenSSF Scorecard tende a >= 8.

## 16. P3 — Comparazione pubblica ma onesta

Aggiungi `docs/COMPARISON.md`, ma senza attaccare altri progetti.

Tabella consigliata:

| Tool | Focus | SafeDeps differenza |
|---|---|---|
| Tool runtime firewall | Bloccare installazioni npm/PyPI malevole | SafeDeps punta anche a policy locale, UI, NuGet, CI, AI-agent workflows. |
| pip-audit | Audit vulnerabilità Python | SafeDeps è preventivo e policy-based; può integrare audit, non sostituirlo. |
| osv-scanner | Vulnerability scanning multi-ecosystem | SafeDeps aggiunge guard runtime e policy approval. |
| GitHub Dependency Review | PR dependency diff | SafeDeps lavora anche localmente prima della PR. |
| npm audit | Vulnerability audit npm | SafeDeps controlla anche policy, lockfile, direct URL, guard. |

Criterio “done”:

- chi legge capisce perché SafeDeps esiste anche se usa già altri tool.

## 17. P3 — “SafeDeps Action”

Quando la CLI è stabile, crea una GitHub Action ufficiale.

### 17.1 API minima

```yaml
- uses: jaydemks/safedeps-action@v1
  with:
    path: .
    fail-on: HIGH
    policy: .safedeps/policy.json
    sarif: true
```

### 17.2 Criteri

- Action testata con repository fixture.
- Action pubblica SARIF come artifact.
- Action fallisce con exit code stabile.
- Action usa versioni pinned.
- README dedicato con esempi.

Questa è una feature ad alto impatto perché abbassa la barriera d’ingresso.

## 18. Cose da NON fare ora

Queste cose sembrano produttive ma rischiano di peggiorare il progetto:

- non aggiungere altri ecosystem prima di stabilizzare pip/npm/NuGet;
- non investire troppo nella UI prima che guard/scanner siano solidi;
- non promettere protezione totale da pacchetti malevoli;
- non creare nuove euristiche senza test e falsi positivi documentati;
- non fare release frequenti senza compatibility matrix;
- non nascondere che npm/NuGet sono experimental se non sono ancora coperti da CI e2e;
- non lasciare la CLI diventare il centro di tutta la logica.

## 19. Ordine consigliato dei commit

1. `docs: add known limitations and threat model skeleton`
2. `dev: add ruff, coverage, mypy and make checks`
3. `ci: add quality workflow`
4. `tests: split cli tests into unit and integration suites`
5. `tests: add golden report fixtures`
6. `ci: add os and python matrix`
7. `guard: isolate wrapper generation modules`
8. `tests: add guard wrapper tests for bash powershell cmd`
9. `core: introduce PackageTarget Finding PolicyDecision models`
10. `ecosystems: add package manager adapter interface`
11. `ecosystems-pip: move pip parsing and command inspection into adapter`
12. `tests-pip: add pip e2e guard matrix`
13. `policy: add json schema and validation command`
14. `docs: document policy and approvals`
15. `security: add codeql dependency-review dependabot scorecard`
16. `release: add trusted publishing workflow`
17. `docs: rewrite README with stable/experimental support matrix`
18. `ecosystems-npm: add npm e2e matrix`
19. `ecosystems-nuget: add dotnet e2e matrix`
20. `action: add safedeps GitHub Action`

## 20. Roadmap per versioni

### v0.4 — Stabilization release

Obiettivo: rendere SafeDeps verificabile e credibile senza aggiungere nuove feature.

Stato al 2026-06-19:

- [x] version bump a `0.4.0`;
- [x] release note attiva `RELEASE_NOTES_2026-06-18.md`;
- [x] test suite iniziata in `tests/unit/` per aree critiche;
- [x] `make checks`;
- [x] ruff + typecheck + coverage gate;
- [x] coverage gate portato a 80%;
- [x] build package + `twine check` + CLI smoke nel gate;
- [x] threat model iniziale;
- [x] README e docs con limitation/support matrix;
- [x] policy/approvals/bypass docs iniziali;
- [x] CI quality/security scaffolding;
- [x] OS/Python/shell/package-manager matrix profonda;
- [x] pip e2e minimo separato dalla suite CLI storica;
- [x] release preflight finale per versione `0.4.0`;
- [x] guida review finale `docs/maintainers/PRE_RELEASE_REVIEW.md`;
- [ ] tag `v0.4.0`.

Non deve includere:

- nuove promesse su npm/NuGet;
- nuove UI grosse;
- nuovi ecosystem.

### v0.5 — Guard hardening

Obiettivo: rendere credibile la parte più fragile.

Deve includere:

- test wrapper Bash/PowerShell/CMD;
- runtime guard testato su `python -m pip`;
- project/global scope testati;
- cleanup/idempotenza testati;
- [x] `safedeps doctor` più severo;
- messaggi di errore migliorati.

### v0.6 — Multi-ecosystem truth release

Obiettivo: decidere cosa è davvero supportato.

Deve includere:

- npm e2e matrix;
- NuGet scan matrix;
- NuGet runtime guard solo se testato davvero;
- `docs/ECOSYSTEM_SUPPORT.md` completo;
- README aggiornato con supported/partial/experimental.

### v0.7 — Verifiers release

Obiettivo: rafforzare SafeDeps sul piano “policy + signals”.

Deve includere:

- OSV verifier stabile;
- local malicious/vulnerability feed;
- package age verifier;
- direct URL / git URL verifier;
- dependency confusion policy;
- provenance/attestation check sperimentale;
- docs per ogni verifier.

### v0.8 — CI/productization release

Obiettivo: farlo adottare facilmente.

Deve includere:

- GitHub Action;
- SARIF upload docs;
- pre-commit docs;
- GitLab/Azure CI examples;
- HTML report migliorato;
- comparison doc.

### v1.0 — Trust release

SafeDeps può dichiararsi v1.0 solo quando:

- Python/pip è stabile su OS matrix;
- npm è stabile o chiaramente limited;
- NuGet è stabile o chiaramente limited;
- coverage totale >= 90%;
- CI include e2e reali;
- threat model completo;
- release PyPI con Trusted Publishing/attestations;
- SECURITY.md presente;
- OpenSSF Scorecard >= 8;
- nessuna feature dichiarata stabile senza test.

### Backlog non bloccante per `v0.4.0`

I seguenti punti restano intenzionalmente post-`v0.4.0` e non devono bloccare la Beta Preview stabilization release finché README/docs li descrivono come limitati, experimental o non garantiti:

- edge case pip avanzati: constraint-file combinati, install locale/editable, wheel URL, local path, index URL complessi;
- casi npm avanzati: workspace, alias, git dependency, tarball URL, local path;
- source privati NuGet e runtime guard NuGet;
- migrazioni future dello schema policy e famiglia dedicata `safedeps policy ...`;
- Trusted Publishing e attestations fino a validazione reale del workflow di release.

La review finale per `0.4.0` è guidata da `docs/maintainers/PRE_RELEASE_REVIEW.md`.

## 21. Checklist finale “progetto da 9/10”

### Engineering

- [x] Test piccoli e separati per modulo.
- [x] Coverage >= 90%.
- [x] CI OS/Python/shell/package-manager matrix.
- [x] Type checking attivo.
- [x] Lint/format obbligatori.
- [x] Build package testata.
- [ ] Release da tag.

### Security

- [x] Threat model.
- [x] SECURITY.md.
- [x] CodeQL.
- [x] Dependency Review.
- [x] Dependabot.
- [x] OpenSSF Scorecard.
- [ ] PyPI Trusted Publishing.
- [ ] Attestations quando disponibili.
- [x] SARIF upload.

### Product

- [x] README chiaro sotto 90 secondi.
- [x] Quickstart reale.
- [x] Esempi per Python, Node, .NET.
- [x] Support matrix onesta.
- [x] Comparison doc.
- [x] Messaggi di errore con fix.
- [x] `safedeps doctor` utile.

### Architecture

- [x] CLI sottile.
- [x] Core models stabili.
- [x] Package manager adapter.
- [x] Verifier interface.
- [x] Reporter interface.
- [x] Guard backend isolato.
- [x] Policy schema versionato.

## 22. Il punto più importante

SafeDeps non deve diventare più grande subito. Deve diventare più dimostrabile.

La strada giusta è:

1. rendere Python/pip solidissimo;
2. dichiarare npm/NuGet experimental finché non sono coperti da e2e;
3. costruire una CI molto più severa;
4. scrivere un threat model onesto;
5. modularizzare adapter/verifier/reporter;
6. solo dopo spingere marketing, UI e nuove feature.

Se fai questo, SafeDeps può diventare molto credibile in una cosa precisa: non solo bloccare pacchetti malevoli noti, ma diventare un **policy firewall locale e CI-first per dependency changes generati anche da AI agent**.

Quella è la posizione forte. Tutto il resto deve servire a dimostrarla.

## 23. Riferimenti usati per il benchmark

- SafeDeps repository: https://github.com/jaydemks/SafeDeps
- SafeDeps README: https://raw.githubusercontent.com/jaydemks/SafeDeps/main/README.md
- SafeDeps pyproject: https://raw.githubusercontent.com/jaydemks/SafeDeps/main/pyproject.toml
- SafeDeps CI: https://raw.githubusercontent.com/jaydemks/SafeDeps/main/.github/workflows/ci.yml
- SafeDeps pre-commit: https://raw.githubusercontent.com/jaydemks/SafeDeps/main/.pre-commit-config.yaml
- SafeDeps tests tree: https://github.com/jaydemks/SafeDeps/tree/main/tests
- Datasette repository: https://github.com/simonw/datasette
- Datasette pyproject: https://raw.githubusercontent.com/simonw/datasette/main/pyproject.toml
- Datasette tests tree: https://github.com/simonw/datasette/tree/main/tests
- OpenSSF Scorecard: https://github.com/ossf/scorecard
- PyPI attestations documentation: https://docs.pypi.org/attestations/
- GitHub CodeQL documentation: https://docs.github.com/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning-with-codeql
- GitHub Dependency Review Action: https://github.com/actions/dependency-review-action
- GitHub Dependabot security updates: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates
