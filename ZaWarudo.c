#include <linux/module.h> //Needed by all modules 
#include <linux/printk.h> //Needed for pr_info() 
#include <linux/string.h>


typedef enum {
    TRAP_OKAY,
    TRAP_CPU_UNSUPPORTED,
    TRAP_VMX_UNSUPPORTED
} Trap;


void enable_enter_vmx_operation(void){

}

Trap check_cpu_compatibility(void) {
    
    //Checking if intel CPU
    //Table 3-17
    //Executes the CPUID instruction with a value of 0H in the EAX register, then reads the EBX, ECX, and EDX registers to determine if the BSP is “GenuineIntel.
    int vendor[3];
    char vendor_str[13] = {0};

    asm("mov $0, %eax");
    asm("cpuid");
    asm("mov %%ebx, %0" : "=r"(vendor[0]));
    asm("mov %%edx, %0" : "=r"(vendor[1]));
    asm("mov %%ecx, %0" : "=r"(vendor[2]));
    
    memcpy(&vendor_str, &vendor, sizeof(vendor));
    
    if(strcmp(vendor_str, "GenuineIntel"))
        return TRAP_CPU_UNSUPPORTED;

    
    //Checking if VMX is supported
    //Section 23.6
    //If CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported
    int cpuid_output = 0;

    asm(
        "mov $1, %%rax\n"
        "cpuid\n"
        "mov %%ecx, %0" : "=r"(cpuid_output)
    );
    
    int vmx_support = (cpuid_output >> 5) & 1 ;
    if(!vmx_support)   
        return TRAP_VMX_UNSUPPORTED;


    return TRAP_OKAY;
}


static int __init entry(void) {

    Trap cpu_compatible = check_cpu_compatibility();
    if(cpu_compatible != TRAP_OKAY) {
        pr_err("ZaWarudo: ERROR: %d\n", cpu_compatible);
        return 0;
    }   
    
    enable_enter_vmx_operation();

    return 0;
}


static void __exit exit(void) {
    pr_info("Goodbye world \n");
}


module_init(entry);
module_exit(exit);


MODULE_LICENSE("GPL v3");
MODULE_AUTHOR("Deep");
MODULE_DESCRIPTION("A Simple Hypervisior ");