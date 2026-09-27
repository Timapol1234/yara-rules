#!/usr/bin/env bash
# Прогон всех правил из rules/ по каталогу samples/
# Использование: ./scan.sh [каталог]
TARGET="${1:-samples}"
for rule in rules/*.yar; do
    echo "== $rule =="
    yara -r "$rule" "$TARGET"
done
