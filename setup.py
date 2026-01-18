from setuptools import setup, find_packages

setup(
    name="joscanzuj",
    version="1.0.0",
    author="ZUJ Cyber Security Students",
    description="AI-Powered Web Vulnerability Scanner",
    packages=find_packages(),
    install_requires=[
        'customtkinter>=5.2.0',
        'requests>=2.28.0',
        'selenium>=4.10.0',
        'reportlab>=4.0.0',
        'colorama>=0.4.6',
        'webdriver-manager>=4.0.0',
    ],
    entry_points={
        'console_scripts': [
            'joscanzuj=joscanzuj:main',
        ],
    },
)