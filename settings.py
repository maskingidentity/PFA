############################################################
#### Description:
# debuggin settings.

# Author: Nikhil Vanjani
############################################################

# Set DEBUG to True to get a detailed debug output including
# intermediate values during key generation, signing, and
# verification. This is implemented via calls to the
# debug_print_vars(DEBUG) function.
#
# If you want to print values on an individual basis, use
# the pretty() function, e.g., print(pretty(foo)).
def init():
	global DEBUG
	# DEBUG = True
	DEBUG = False