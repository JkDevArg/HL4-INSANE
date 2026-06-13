"""Paquete interno LEGITIMO acme-utils v1.0.0 (baseline del registry).

Es benigno: solo expone utilidades de formato. El reto consiste en publicar
una version MAYOR maliciosa que sustituya a esta en el build.
"""
from setuptools import setup

setup(
    name="acme-utils",
    version="1.0.0",
    description="ACME internal utils (legit baseline)",
    py_modules=["acme_utils"],
    python_requires=">=3.8",
)
