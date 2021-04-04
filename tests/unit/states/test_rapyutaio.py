import pytest
import salt.modules.test as testmod
import saltext.rapyutaio.modules.rapyutaio_mod as rapyutaio_module
import saltext.rapyutaio.states.rapyutaio_mod as rapyutaio_state


@pytest.fixture
def configure_loader_modules():
    return {
        rapyutaio_module: {
            "__salt__": {
                "test.echo": testmod.echo,
            },
        },
        rapyutaio_state: {
            "__salt__": {
                "rapyutaio.example_function": rapyutaio_module.example_function,
            },
        },
    }


def test_replace_this_this_with_something_meaningful():
    echo_str = "Echoed!"
    expected = {
        "name": echo_str,
        "changes": {},
        "result": True,
        "comment": "The 'rapyutaio.example_function' returned: '{}'".format(echo_str),
    }
    assert rapyutaio_state.exampled(echo_str) == expected
