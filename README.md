# Shellcode Maker

+ Explore Shellcode Development
+ Сформировать Shellcode для исполняемых файлов Windows (PE) архитектур x86/x64

## shell_builder

+ проект содержит байткоды рефлективных загрузчиков PE исполняемых файлов для x86/x64 архитектур
+ формирует Shellcode из входного PE исполняемого файла

```PYTHON
> shell_builder.exe
  Usage: shell_builder.exe [PATH_TO_PE]
```

## shell_loader

+ проект содержит сборщик рефлективных загрузчиков PE исполняемых файлов для архитектур x86/x64
+ после сборки необоходимо получить байткоды загрузчиков через `text_parser`

## text_parser

+ формирует байткоды для `shell_loader'ов`

## bin

+ содержит загрузчики `runshc32.exe` и `runshc64.exe` для шеллкодов x86/x64 архитектур
+ `test_binaries` - тестовые PE

## Пример работы

![alt text](/img/shell_maker.gif)

## Ссылки

+ https://github.com/TheWover/donut
+ https://github.com/hasherezade/pe_to_shellcode
+ https://github.com/4l3x777/reflective_loader
