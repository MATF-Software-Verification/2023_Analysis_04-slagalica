import subprocess
import os
import sys

# pozivanje sa stilom iz .clang-format fajla:
# python3 run_clang_format.py dir

# pozivanje sa predefinisanim stilom:
# python3 run_clang_format.py naziv_stila


# f-ja proverava da li je fajl C++
def isCppFile(filename):
    return filename.endswith('.h') \
        or filename.endswith('.c') \
        or filename.endswith('.hpp') \
        or filename.endswith('.cpp') \


if __name__ == "__main__":
    # 0-ti argument je naziv skripte pa ga preskacemo 
    args = sys.argv[1:]
    
    # neispravno koriscenje 
    if len(args) < 1:
        exit(1)
     
    # ako imamo 1 argument to je direktorijum i pozivamo clang-format sa stilom definisanim u .clang-format fajlu     
    dir = args[0]
    
    # ako imamo 2 ili vise argumenata (nakon 2. se ignorisu) prvi je direktorijum a drugi je ime ugradjenog stila
    if len(args) > 1:
        style = args[1]
	
    # rekurzivni obilazak direktorijuma		
    for dir, _, files in os.walk(dir):
        for filename in files:
            filepath = dir + '/' + filename
            # za C++ fajlove pozivamo clang-format
            if isCppFile(filename):
                # nije definisan stil
                if len(args) == 1:
                    subprocess.run('clang-format -i {}'.format(filepath), shell=True)
                # definisan stil	
                else:
                    subprocess.run('clang-format -i  -style={} {}'.format(style, filepath), shell=True)
                		
