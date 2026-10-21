import login_anomaly


def test_package_imports_and_has_version() -> None:
    assert isinstance(login_anomaly.__version__, str)
    assert login_anomaly.__version__ != ""
