module gc.impl.vulture.bits;

struct BitArray
{
nothrow:
	ubyte opIndex(size_t i)
	{
		return 0;
	}

	ubyte opIndexAssign(ubyte v, size_t i)
	{
		return 0;
	}

	void opSliceAssign(ubyte v, size_t s, size_t e)
	{

	}	
}

struct NibbleArray
{
nothrow:
	ubyte opIndex(size_t i)
	{
		return 0;
	}

	ubyte opIndexAssign(ubyte v, size_t i)
	{
		return 0;
	}

	ubyte opIndexOpAssign(string op)(ubyte v, size_t i)
	if(op == "|" || op == "&")
	{
		return 0;
	}

	void opSliceAssign(ubyte v, size_t s, size_t e)
	{

	}
}
