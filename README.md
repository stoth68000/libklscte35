Installing LibKLSCTE35
======================

## License:
***********

* LGPL-V2.1
* See the included lgpl-2.1.txt for the complete license agreement.


## Compilation:
***************

	./autogen.sh --build
	./configure --enable-shared=no
	make
	make install


## Dependencies:
****************
The following is a list of dependencies needed to successfully install LibKLSCTE35:

* automake
	- macOS - `brew install automake`
* libtool
	- macOS - `brew install libtool`
* libklvanc
	- macOS - [follow instructions here](https://github.com/stoth68000/libklvanc)


## Documentation:
*****************
To make doxygen documentation in the doxygen folder, run the following command:

        make docs

To view the documentation, cd into the doxygen/html/ directory and open the index.html file in a browser window.
