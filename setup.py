from setuptools import setup, find_packages

setup(
    name="ics_finder",
    version="0.1.0",
    description="Scan IP ranges (excluding MISP warning lists) for Modbus/SCADA/PLC devices",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
    ],
    entry_points={
        "console_scripts": [
            "ics_finder=ics_finder.main:main",
            "ics_finder_dashboard=ics_finder.webapp:main",
        ],
    },
)
