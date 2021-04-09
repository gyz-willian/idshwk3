global gyz :table[addr] of set[string];

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (to_lower(name)=="user-agent")
	{
		if (c$id$orig_h in gyz) 
	  {
		  add gyz[c$id$orig_h][value];
	  }
	  else
	  {
		  gyz[c$id$orig_h]=set(value);
	  }
	}
}

event zeek_done()
{
	for (x in gyz)
	{
		if( |gyz[x]|>=3)
		print fmt("%s is a proxy",x);
	}
}
