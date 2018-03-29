from setuptools import setup
import sys


def get_install_requires():
    install_requires = ['skydive-client>=0.4.2']


setup(name='skydive-flow-matrix',
      version='0.0.1',
      description='Return flow matrix',
      url='http://github.com/skydive-project/skydive',
      author='Sylvain Afchain',
      author_email='safchain@gmail.com',
      license='Apache2',
      packages=['matrix'],
      entry_points={
        'console_scripts': [
            'skydive-flow-matrix = matrix.matrix:main',
        ],
      },
      install_requires=get_install_requires(),
      zip_safe=False)

