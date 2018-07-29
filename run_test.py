import os
import filecmp

# This is a non working attempt at an automatic testing script. I need to learn python :/
for test in os.listdir('tests'):
    os.system('python3 sniffer.py tests/{} > test_output'.format(test))
    outcome = filecmp.cmp('test_output', 'outputs/ipv4_icmp_test_output')
    if outcome == True:
        print("Pass: {}".format(test))
    elif outcome == False:
        print("Fail: {}".format(test))
    else:
        print("Invalid outcome")
os.system('rm test_output')