import subprocess

from helpers import python_command


def test_python_command_preserves_multiline_script():
    script = '''
value = "it's intact"
print(value)
'''

    result = subprocess.run(
        python_command(script),
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "it's intact\n"


def test_python_command_can_request_sudo():
    assert python_command("print(42)", sudo=True).startswith("sudo python3 -c ")
