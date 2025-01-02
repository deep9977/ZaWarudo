#include <linux/module.h> //Needed by all modules 
#include <linux/printk.h> //Needed for pr_info() 
#include <linux/string.h>
#include <asm/msr.h>
#include <linux/mm.h>
#include <asm/page.h>


#define MSR_IA32_FEATURE_CONTROL 0x3A
#define MSR_IA32_VMX_CR0_FIXED0 0x486
#define MSR_IA32_VMX_CR0_FIXED1 0x487
#define MSR_IA32_VMX_CR4_FIXED0 0x488
#define MSR_IA32_VMX_CR4_FIXED1 0x489
#define MSR_IA32_VMX_BASIC 0x480

typedef enum {
    TRAP_OKAY,
    TRAP_CPU_UNSUPPORTED,
    TRAP_VMX_UNSUPPORTED,
    TRAP_UNABLE_TO_ALLOCATE_MEM,
    TRAP_VMXON_FAILED
} Trap;


Trap enable_enter_vmx_operation(void){
    
    //Section 23.7
    
    //enables VMX by setting CR4.VMXE[bit 13] = 1
    long unsigned int cr4v;
    asm volatile("mov  %%cr4, %0" : "=r"(cr4v));

    int is_cr4_set = (cr4v >> 13) & 1;

    if(!is_cr4_set){
        unsigned long one = 1;
        cr4v |= one << 13;
        asm volatile("mov %0, %%cr4" : : "r" (cr4v));
    }
    

    //Configure IA32_FEATURE_CONTROL MSR to allow VMXON
    /*
        VMXON is also controlled by the IA32_FEATURE_CONTROL MSR (MSR address 3AH). This MSR is cleared to zero
        when a logical processor is reset. The relevant bits of the MSR are:
        
        •Bit 0 is the lock bit. If this bit is clear, VMXON causes a general-protection exception. If the lock bit is set,
        WRMSR to this MSR causes a general-protection exception;

        •Bit 1 enables VMXON in SMX operation. If this bit is clear, execution of VMXON in SMX operation causes a
        general-protection exception.
        
        • Bit 2 enables VMXON outside SMX operation. If this bit is clear, execution of VMXON outside SMX
        operation causes a general-protection exception. 
    */

    unsigned long int msrv, temp = (1 << 2) | (1 << 0);
    
    rdmsrl(MSR_IA32_FEATURE_CONTROL, msrv);
    
    if((temp & msrv) != temp){
        msrv |= temp;
        wrmsrl(MSR_IA32_FEATURE_CONTROL, msrv);
    }


    //Section 23.8
    //In VMX operation, processors may fix certain bits in CR0 and CR4 to specific values and not support other values. 
    /*
    Appendix A.7 & Appendix A.8
        If bit X is 1 in FIXED0, then that bit of CR0 is fixed to 1 in VMX operation
        if bit X is 0 in FIXED1, then that bit of CR0 is fixed to 0 in VMX operation. 
        
        The IA32_VMX_CR0_FIXED0 MSR (index 486H) and IA32_VMX_CR0_FIXED1 MSR (index 487H)
        The IA32_VMX_CR4_FIXED0 MSR (index 488H) and IA32_VMX_CR4_FIXED1 MSR (index 489H) 
    */
    unsigned long cr0v;

    asm volatile("mov %%cr0, %0" : "=r" (cr0v));
    asm volatile("mov %%cr4, %0" : "=r" (cr4v));

    rdmsrl(MSR_IA32_VMX_CR0_FIXED0, temp);
    cr0v |= temp;
    rdmsrl(MSR_IA32_VMX_CR0_FIXED1, temp);
    cr0v &= temp;

    rdmsrl(MSR_IA32_VMX_CR4_FIXED0, temp);
    cr4v |= temp;
    rdmsrl(MSR_IA32_VMX_CR4_FIXED1, temp);
    cr4v &= temp;

    asm volatile("mov %0, %%cr0" : : "r" (cr0v));
    asm volatile("mov %0, %%cr4" : : "r" (cr4v));

    
    /*
    Section 24.11.5
        Before executing VMXON, software allocates a region of memory (called the VMXON region)
        The physical address of this region (the VMXON pointer) is provided in an operand to VMXON. 
        • The VMXON pointer must be 4-KByte aligned (bits 11:0 must be zero).
        • The VMXON pointer must not set any bits beyond the processor’s physical-address width.2,3

        Before executing VMXON, software should write the VMCS revision identifier (see Section 24.2) to the VMXON region.
    */

    unsigned long int* vmxon_region = kzalloc(4096, GFP_KERNEL); 
    if(vmxon_region == NULL) 
        return TRAP_UNABLE_TO_ALLOCATE_MEM;

    //If you have a logical address, the macro __pa() (defined in <asm/page.h>) will return its associated physical address.
    unsigned long int physical_address = __pa(vmxon_region);

    //writing VMCS revision identifier 
    rdmsrl(MSR_IA32_VMX_BASIC, temp);
    *(unsigned int*)vmxon_region = (unsigned int)temp;


    //executing VMXON
    uint8_t vmxon_result = 0;
	asm volatile("vmxon %[pa]; setna %[vr]"
		: [vr]"=rm"(vmxon_result)
		: [pa]"m"(physical_address)
		: "cc", "memory");
    
    if(vmxon_result != 0)
        return TRAP_VMXON_FAILED;


    return TRAP_OKAY;
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
    Trap trap = 0;

    trap = check_cpu_compatibility();
    if(trap) {
        pr_err("ZaWarudo: ERROR: check_cpu_compatibility(): %d\n", trap);
        return 0;
    }pr_info("ZaWarudo: CPU compatible");
    
    trap = enable_enter_vmx_operation();
    if(trap){
        pr_err("ZaWarudo: ERROR: enable_enter_vmx_operation(): %d\n", trap);
        return 0;
    }pr_info("ZaWarudo: vmxon successful");


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