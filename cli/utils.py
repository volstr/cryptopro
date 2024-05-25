from typing import List


def build_command_line_args(command: str, *args, **kwargs) -> List[str]:
    """Создает список аргументов командной строки для subprocess.Popen"""
    arguments = [command]
    # Позиционные параметры
    for arg in args:
        if arg and isinstance(arg, str):
            arguments.append(arg)

    # Именованные параметры со значением True превращаем в позиционные
    for key, value in kwargs.items():
        if isinstance(value, bool) and value:
            arguments.append(f'-{key}')

    # Именованные параметры
    for key, value in kwargs.items():
        if (value or isinstance(value, int)) and not isinstance(value, bool):
            arguments.append(f'-{key}')
            arguments.append(str(value))

    return arguments
