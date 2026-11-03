# sophos-auto-usbscan

[![build](https://github.com/loardracoon/sophos-auto-usbscan/actions/workflows/build.yml/badge.svg)](https://github.com/loardracoon/sophos-auto-usbscan/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Varredura antivírus automática de pendrives e discos USB para Windows, Linux e macOS.**
O programa se chama `usbscan`.

Serviço leve e multiplataforma (Linux, Windows e macOS), escrito em Rust, que
dispara uma varredura antivírus **sempre que um pendrive ou disco USB é
conectado**. É um binário único, sem dependências (não precisa de PowerShell,
udisks2, jq ou udev), que se instala sozinho como serviço do sistema.

- [Por que existe](#por-que-existe)
- [Como funciona](#como-funciona)
- [Instalação no Linux](#instalação-no-linux)
- [Instalação no Windows](#instalação-no-windows)
- [Instalação no macOS](#instalação-no-macos)
- [Compilar a partir do código-fonte](#compilar-a-partir-do-código-fonte)
- [Configuração](#configuração)
- [Comandos](#comandos)
- [Verificar se está funcionando](#verificar-se-está-funcionando)
- [Implantação em massa](#implantação-em-massa)
- [Solução de problemas](#solução-de-problemas)
- [Publicar uma versão](#publicar-uma-versão)

---

## Por que existe

A proteção em tempo real (on-access) do Sophos só inspeciona — e só alerta —
quando um arquivo é **aberto ou lido**. Um pendrive conectado cujos arquivos
ninguém abre nunca é verificado e nunca gera alerta no Sophos Central.

O usbscan resolve isso verificando ativamente cada volume USB assim que ele é
montado.

## Como funciona

### Estratégias de varredura

| modo    | o que faz |
|---------|-----------|
| `auto`  | **padrão** — usa o scanner sob demanda se estiver instalado; senão, `touch` |
| `cli`   | executa o scanner sob demanda do Sophos no ponto de montagem do pendrive |
| `touch` | percorre o volume e abre/lê o início de cada arquivo, obrigando a proteção em tempo real a inspecionar cada um e a gerar o alerta |
| `both`  | `cli` e, em seguida, `touch` |

Scanners detectados automaticamente (caminho e argumentos podem ser alterados
na configuração):

| Sistema | Binário | Argumentos |
|---------|---------|------------|
| Linux | `/opt/sophos-spl/plugins/av/bin/avscanner` | `{path} --scan-archives` |
| Linux (legado) | `/opt/sophos-av/bin/savscan` | `-archive {path}` |
| Windows | `C:\Program Files\Sophos\Endpoint Defense\SophosInterceptXCLI.exe` | `scan --noui --expand_archives {path}` |
| Windows (legado) | `C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sav32cli.exe` | `-archive {path}` |
| macOS | `/usr/local/bin/sweep` | `-archive {path}` |

**Resultado:** saída `0` do scanner = limpo, e o dispositivo entra no cache.
Qualquer outro código (ameaça ou erro) é registrado como `ALERT/FAIL` e o
dispositivo **não** entra no cache, sendo verificado de novo na próxima
inserção. No modo `touch`, arquivos cuja leitura é bloqueada pelo antivírus
(acesso negado / `ERROR_VIRUS_INFECTED`) são registrados como possível ameaça.

### Detecção do USB

| Sistema | Mecanismo |
|---------|-----------|
| Linux | Acorda a cada montagem/desmontagem (`poll` em `/proc/self/mountinfo`) e identifica o USB pelo sysfs. A opção `auto_mount` monta somente-leitura as partições que ninguém montou (servidores sem interface gráfica) e desmonta após a varredura. |
| macOS | Observa `/Volumes` (`kqueue`) e confirma com `diskutil` que o disco é USB. |
| Windows | Serviço nativo; consulta as letras de unidade a cada 2 s (custo desprezível) e identifica o barramento USB. Detecta também HDs/SSDs USB que o Windows mostra como disco fixo. |

Consumo medido no Linux: binário de ~430 KB, ~2 MB de RAM e 0 % de CPU parado.

---

## Instalação no Linux

**Requisitos:** x86_64 ou ARM64, systemd, acesso root. Sophos Protection for
Linux (SPL) recomendado para o modo `cli`.

### Opção A — instalador automático

```bash
curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
```

O script detecta a arquitetura, baixa o binário da última Release, confere o
SHA-256 e executa `usbscan install`. Para fixar uma versão:
`curl ... | sudo USBSCAN_VERSION=v0.1.0 sh`.

### Opção B — manual

```bash
curl -fsSLO https://github.com/loardracoon/sophos-auto-usbscan/releases/latest/download/usbscan-linux-x86_64
```
```bash
chmod +x usbscan-linux-x86_64
```
```bash
sudo ./usbscan-linux-x86_64 install
```

(Em ARM64 use `usbscan-linux-aarch64`.) Os binários Linux são estáticos (musl)
e funcionam em qualquer distribuição.

### O que o `install` faz

| Item | Local |
|------|-------|
| Binário | `/usr/local/bin/usbscan` |
| Configuração | `/etc/usbscan.conf` (criada só se não existir) |
| Serviço | `/etc/systemd/system/usbscan.service` (habilitado e iniciado) |
| Log | `/var/log/usbscan.log` |
| Cache | `/var/lib/usbscan/cache.tsv` |

### Verificar

```bash
systemctl status usbscan
```
```bash
tail -f /var/log/usbscan.log
```

### Servidores sem interface gráfica

Sem um automontador (GNOME/KDE/udisks), o pendrive não é montado e não há o
que verificar. Ative em `/etc/usbscan.conf`:

```ini
auto_mount = true
```
```bash
sudo systemctl restart usbscan
```

### Atualizar / desinstalar

Atualizar: rode o instalador de novo (ou `sudo ./usbscan-novo install`).

```bash
sudo usbscan uninstall
```

A desinstalação mantém configuração, cache e log. Para apagar tudo:
`sudo rm -rf /etc/usbscan.conf /var/lib/usbscan /var/log/usbscan.log*`.

---

## Instalação no Windows

**Requisitos:** Windows 10/11 ou Server 2016+ (x64), conta de Administrador.
Sophos Intercept X / Endpoint recomendado para o modo `cli`.

### Opção A — instalador automático

Abra o **PowerShell como Administrador**:

```powershell
irm https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.ps1 | iex
```

O script baixa `usbscan-windows-x86_64.exe` da última Release, confere o
SHA-256 e executa `usbscan install`.

### Opção B — manual

1. Baixe `usbscan-windows-x86_64.exe` na página
   [Releases](https://github.com/loardracoon/sophos-auto-usbscan/releases).
2. Se baixou pelo navegador, clique com o botão direito → Propriedades →
   marque **Desbloquear** (ou rode `Unblock-File .\usbscan-windows-x86_64.exe`).
3. Em um prompt **como Administrador**:

```bat
usbscan-windows-x86_64.exe install
```

### O que o `install` faz

| Item | Local |
|------|-------|
| Binário | `C:\Program Files\usbscan\usbscan.exe` |
| Configuração | `C:\ProgramData\usbscan\usbscan.conf` |
| Serviço | `usbscan` — "USB Antivirus Scan Trigger", início automático, conta LocalSystem, reinício automático em falha |
| Log | `C:\ProgramData\usbscan\usbscan.log` |
| Cache | `C:\ProgramData\usbscan\cache.tsv` |

### Verificar

```powershell
Get-Service usbscan
```
```powershell
Get-Content C:\ProgramData\usbscan\usbscan.log -Wait -Tail 20
```

### Atualizar / desinstalar

Atualizar: rode o instalador de novo — o serviço é parado, o binário trocado e
o serviço reiniciado.

```bat
"C:\Program Files\usbscan\usbscan.exe" uninstall
```

Para apagar também configuração e log: `rmdir /s /q C:\ProgramData\usbscan`.

---

## Instalação no macOS

**Requisitos:** macOS 11 ou superior (Intel ou Apple Silicon), conta de
administrador.

### Opção A — instalador automático

```bash
curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
```

### Opção B — manual

```bash
curl -fsSLO https://github.com/loardracoon/sophos-auto-usbscan/releases/latest/download/usbscan-macos-aarch64
```
```bash
chmod +x usbscan-macos-aarch64
```
```bash
xattr -d com.apple.quarantine usbscan-macos-aarch64 2>/dev/null; true
```
```bash
sudo ./usbscan-macos-aarch64 install
```

(Em Macs Intel use `usbscan-macos-x86_64`.)

### Passo obrigatório: Acesso Total ao Disco

O macOS bloqueia a leitura de volumes removíveis por processos sem permissão.
Abra **Ajustes do Sistema → Privacidade e Segurança → Acesso Total ao Disco**,
clique em **+**, pressione `⌘⇧G`, digite `/usr/local/bin/usbscan` e ative.
Depois reinicie o serviço:

```bash
sudo launchctl kickstart -k system/com.usbscan.daemon
```

Em frota gerenciada, conceda essa permissão por MDM (perfil PPPC, veja
[Implantação em massa](#implantação-em-massa)).

### O que o `install` faz

| Item | Local |
|------|-------|
| Binário | `/usr/local/bin/usbscan` |
| Configuração | `/etc/usbscan.conf` |
| Serviço | `/Library/LaunchDaemons/com.usbscan.daemon.plist` (carregado, início no boot) |
| Log | `/var/log/usbscan.log` |
| Cache | `/Library/Application Support/usbscan/cache.tsv` |

### Verificar

```bash
sudo launchctl print system/com.usbscan.daemon | head -20
```
```bash
tail -f /var/log/usbscan.log
```

### Atualizar / desinstalar

Atualizar: rode o instalador de novo.

```bash
sudo usbscan uninstall
```

---

## Compilar a partir do código-fonte

Requer [Rust](https://rustup.rs) estável.

```bash
git clone https://github.com/loardracoon/sophos-auto-usbscan
```
```bash
cd sophos-auto-usbscan && cargo build --release
```

O binário fica em `target/release/usbscan` (`usbscan.exe` no Windows). Depois,
`sudo target/release/usbscan install` (ou `usbscan.exe install` como
Administrador).

Binário Linux estático (roda em qualquer distro):

```bash
rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl
```

---

## Configuração

O arquivo é criado comentado pelo `install` e nunca é sobrescrito. Depois de
alterar, reinicie o serviço (`systemctl restart usbscan`,
`Restart-Service usbscan` ou `launchctl kickstart -k system/com.usbscan.daemon`).

| Chave | Padrão | Descrição |
|-------|--------|-----------|
| `mode` | `auto` | `auto`, `cli`, `touch` ou `both` |
| `scanner` | *(auto)* | caminho do scanner sob demanda |
| `scanner_args` | *(auto)* | argumentos; `{path}` vira o ponto de montagem |
| `scan_timeout` | `3600` | segundos até abortar o scanner |
| `settle` | `3` | segundos de espera após a montagem antes de verificar |
| `scan_on_start` | `true` | verificar pendrives já conectados quando o serviço inicia |
| `cache_ttl` | `86400` | não verificar de novo um dispositivo limpo dentro deste prazo (segundos); `0` = sempre verificar |
| `cache_max` | `10` | quantidade de dispositivos guardados no cache |
| `touch_bytes` | `4096` | bytes lidos de cada arquivo no modo `touch` |
| `touch_max_files` | `500000` | limite de arquivos por volume no modo `touch` |
| `touch_max_depth` | `64` | profundidade máxima de pastas no modo `touch` |
| `auto_mount` | `false` | *Linux* — montar somente-leitura partições USB não montadas |
| `poll_ms` | `2000` | *Windows* — intervalo de verificação das unidades |
| `log_file` / `cache_file` | por SO | caminhos alternativos |
| `log_max_bytes` | `5242880` | tamanho para rotacionar o log (`.log.1`) |
| `debug` | `false` | log detalhado |

O cache identifica o dispositivo por fabricante:produto:serial:partição
(Linux), modelo:UUID do volume (macOS) ou fabricante:produto:serial:serial do
volume (Windows). Em ambiente de alto risco use `cache_ttl = 0`: um pendrive
limpo pode ser alterado em outra máquina e reconectado dentro do prazo do cache.

## Comandos

```text
usbscan install   [--config ARQ]            instala e inicia o serviço
usbscan uninstall                           para e remove o serviço
usbscan run       [--debug] [--no-cache]    executa em primeiro plano (diagnóstico)
usbscan scan CAMINHO [--debug]              verifica um caminho agora
usbscan devices                             lista volumes USB montados e o ID do cache
usbscan config                              mostra a configuração efetiva
```

## Verificar se está funcionando

1. Conecte um pendrive e acompanhe o log. Deve aparecer:
   `USB volume detected` → `scan start` → `CLEAN` (ou `ALERT/FAIL`).
2. Teste de detecção: grave o
   [arquivo de teste EICAR](https://www.eicar.org/download-anti-malware-testfile/)
   no pendrive **com a proteção em tempo real desativada** (ou em outra máquina),
   reconecte e confirme o alerta no log e no Sophos Central.
3. `usbscan devices` mostra se o volume está sendo reconhecido como USB.

## Implantação em massa

O instalador é silencioso e idempotente; basta distribuir o binário e executar
`install` com privilégio administrativo.

- **Windows (GPO / Intune / SCCM):** script de inicialização ou Win32 app com
  `usbscan-windows-x86_64.exe install`; desinstalação:
  `"C:\Program Files\usbscan\usbscan.exe" uninstall`. Uma configuração padrão
  pode ser copiada para `C:\ProgramData\usbscan\usbscan.conf` antes do install.
- **Linux (Ansible / Salt / shell):** copie o binário e rode
  `usbscan install`; distribua `/etc/usbscan.conf` pelo gerenciador.
- **macOS (Jamf / Intune / Kandji):** pacote ou script com
  `usbscan-macos-<arch> install`, mais um perfil **PPPC** concedendo
  `SystemPolicyAllFiles` (Acesso Total ao Disco) ao caminho
  `/usr/local/bin/usbscan`.

## Solução de problemas

| Sintoma | Causa provável / solução |
|---------|--------------------------|
| Nada no log ao conectar (Linux) | O pendrive não foi montado: ative `auto_mount = true` |
| `mode=cli but no scanner binary found` | Sophos sem scanner sob demanda nesse caminho: ajuste `scanner =` ou use `mode = touch` |
| `scanner exit code N` | Ameaça encontrada ou erro do scanner; a saída do scanner fica no próprio log |
| macOS: `touched 0 files` / erros de leitura | Falta Acesso Total ao Disco para `/usr/local/bin/usbscan` |
| Windows: `Access is denied` no install | Prompt não está como Administrador |
| Pendrive não é verificado de novo | Está no cache (`BYPASS` no log); use `cache_ttl = 0` ou `usbscan run --no-cache` |
| Diagnóstico detalhado | pare o serviço e rode `usbscan run --debug` |

## Publicar uma versão

O workflow `.github/workflows/build.yml` compila os 5 binários a cada push.
Ao criar uma tag `v*`, ele também publica a Release com os binários e o
`SHA256SUMS` usados pelos instaladores:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## Licença

MIT — veja [LICENSE](LICENSE).
