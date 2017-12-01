


a.	I tested my solutions by first verifying that the example inputs work. I then manipulated different ports and IP addresses to verify that my checkPortRange and checkIPRange functions work, as these are few of the key factors in determining which packet is accepted. I manipulated my input packets around the different restrictions to try and break them. This helped me build a more secure basic firewall.

b.	I chose to concatenate the direction and the protocol strings to one – and this helps shorten search space of a given packet, as there are only four possibilities for the combination of the direction/protocol combination. 

c.	Any refinements I think would be in optimizing how fast we can search which port numbers and IP Addresses are valid. Keeping additional dictionaries to keep track of ranges of valid IP's and ports is a possible solution for this. 


