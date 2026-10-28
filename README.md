# passgen

Учебный CLI-проект на чистом Python **3.10+**: генератор паролей и анализатор их надёжности. Без сторонних зависимостей — запускается где угодно, включая Termux.

## Возможности

- Генерация криптостойких паролей (`secrets`, не `random`!)
- Гарантия хотя бы одного символа из каждого выбранного класса
- Режим «passphrase» — запоминаемые фразы из слов
- Оценка энтропии пароля в битах и примерное время подбора
- Эвристики слабостей: повторы, последовательности, слова из списков утечек
- Цветной вывод, чтение пароля из stdin (не остаётся в истории shell)

## Использование

```bash
# обычный пароль, 16 символов (классы: lower + upper + digits + symbols)
python passgen.py generate

# три пароля по 24 символа, без похожих символов (Il1O0o)
python passgen.py generate -l 24 -n 3 --no-ambiguous

# пароль только из букв и цифр
python passgen.py generate --no-symbols

# парольная фраза из 5 слов
python passgen.py generate --phrase -w 5

# проверить свой пароль (безопаснее через echo и pipe)
echo 'MyP@ssw0rd' | python passgen.py check
python passgen.py check Qw!7#kPz9$Lm2@Vb
```

Пример вывода `check`:

```
Длина:            13
Алфавит:          88 символов
Энтропия:         42.4 бит
Подбор (~):       3.6 ч
Вердикт:          средний
  ⚠ последовательность «qwer...»
```

## Что здесь educational

- **`argparse` с подкомандами** — как у настоящих CLI-утилит (`git`, `docker`)
- **`secrets` vs `random`** — почему для секретов нужен криптостойкий ГПСЧ
- **энтропия** — `log2(алфавит^длина)`, и почему эвристики её «съедают»
- **функциональное разбиение** — чистые функции, которые легко покрыть тестами
- **типизация** подсказки и `list[str] | None` (Python 3.10+)

## Как запушить на GitHub

```bash
cd ~/passgen
git init
git add .
git commit -m "passgen: генератор паролей и анализатор стойкости"

# создай ПУСТОЙ репозиторий на github.com/new (без README),
# затем подставь свой ник:
git remote add origin git@github.com:ВАШ_НИК/passgen.git
git branch -M main
git push -u origin main
```

Если используется HTTPS и токен: `git remote add origin https://github.com/ВАШ_НИК/passgen.git` — логин это ник, пароль это Personal Access Token (Settings → Developer settings → Tokens).

Файл `LICENSE` — MIT, чтобы проект можно было свободно использовать.
