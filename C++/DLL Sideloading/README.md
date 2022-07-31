# LNK and DLL sideloading

This is a recreation of a dropper that could possibly have been used by APT 29 in a campaing according to this article by [Unit42](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/). Citing the article:

> ... this sample was packaged as a self-contained ISO. Included in the ISO was a Windows shortcut (LNK) file, a malicious payload DLL and a legitimate copy of Microsoft OneDrive Updater. Attempts to execute the benign application from the ISO-mounted folder resulted in the loading of the malicious payload as a dependency through a technique known as DLL search order hijacking.

The original malware used [Brute Ratel BRC4](https://bruteratel.com/) but as I don't have access to the tool I've used [Sliver](https://github.com/BishopFox/sliver) from [Bishop Fox](https://twitter.com/bishopfox/) for this PoC.
