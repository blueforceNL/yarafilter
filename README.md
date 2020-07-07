# yarafilter
Filter and deduplicate your yar file collection

# Installation:

    git clone https://github.com/blueforceNL/yarafilter
    cd yarafilter
    sudo python3 setup.py install

Usage:

    python3 yarafilter.py -p directory_with_yar_files
    
    
This is assuming your .yar files are in a directory named "directory_with_yar_files"
   
# What's it for?
    
Like other Incident Response teams, ours has quite the collection of YARA rules. 
And, like at other IR teams, over time the collection morphs into a big mess of overlapping and duplicate rules.
 
You should of course have well maintained sets of rules for specific types of incidents on different platforms. 
This tool is written for those of you that don't.

You just throw all your .yar files in a directory and fire up yarafilter. 
Yarafilter will remove functionally duplicate rules and rename duplicate identifiers (yes, the ones Loki complains about).

The results is a clean ruleset in the directory ./output that you can use for your incident. 
Pro tip: Don't throw away your original files, the filtering can result in losing comments in the .yar files.


# Advanced filtering
   
Filter out all rules depending on Androguard:
  
    python3 yarafilter.py -p directory_with_yar_files -i androguard
    
Filter out all rules authored by John Doe (case insensitive):
  
    python3 yarafilter.py -p directory_with_yar_files -a "john doe"

Filter out all rules with "Linux" in the description (case insensitive):
  
    python3 yarafilter.py -p directory_with_yar_files -d "Linux"
    
# Excluding rules

At some point during your investigation, you'll encounter false positives. 
Move the rules causing the false to a separate directory and re-run yarafilter with:

    python3 yarafilter.py -e exclude_directory -p directory_with_yar_files

If your offending rule is in a .yar file with many other rules, remove that one rule from the file and put it in a .yar file of its own in the exclude directory. 

  
