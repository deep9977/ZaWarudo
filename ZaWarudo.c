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
#define MSR_IA32_VMX_PINBASED_CTLS 0x481
#define PIN_BASED_VM_EXEC_CONTROLS 0x4000
#define MSR_IA32_VMX_PROCBASED_CTLS	0x482
#define PROC_BASED_VM_EXEC_CONTROLS	0x4002
#define EXCEPTION_BITMAP 0x4004
#define VM_EXIT_CONTROLS 0x400c
#define MSR_IA32_VMX_EXIT_CTLS 0x483
#define VM_EXIT_HOST_ADDR_SPACE_SIZE 0x200
#define VM_ENTRY_CONTROLS 0x4012
#define MSR_IA32_VMX_ENTRY_CTLS	0x484
#define VM_ENTRY_IA32E_MODE	0x200

typedef enum {
    TRAP_OKAY,
    TRAP_CPU_UNSUPPORTED,
    TRAP_VMX_UNSUPPORTED,
    TRAP_UNABLE_TO_ALLOCATE_MEM,
    TRAP_VMXON_FAILED,
    TRAP_VMPTRLD_FAILED,
    TRAP_VMCS_INITIALIZATION_FAILED
    
} Trap;


int vmwrite(long unsigned int value, long unsigned int location) {
    uint8_t ret = 0;
    
        asm volatile (
            "vmwrite %[value], %[location]; setna %[ret]"
		    : [ret]"=rm"(ret)
		    : [value]"rm"(value), [location]"r"(location)
		    : "cc", "memory"
        );

    return ret;
}

int init_entry_control_field(void){

    //configuring the VM-entry in same way VM-exit was configured.
    unsigned long int econtrol;
    rdmsrl(MSR_IA32_VMX_ENTRY_CTLS, econtrol);

    unsigned int econtrol_final = econtrol | VM_ENTRY_IA32E_MODE; 

    return vmwrite(econtrol_final, VM_ENTRY_CONTROLS);
}

int init_exit_control_field(void){
    
    //The VM-exit controls constitute a 32-bit vector that governs the basic operation of VM exits.
    //need to set bits 9-Host address space size to 1 and can put the remaining bits from MSR_IA32_VMX_EXIT_CTLS.
    unsigned long int econtrol;
    rdmsrl(MSR_IA32_VMX_EXIT_CTLS, econtrol);

    unsigned int econtrol_final = econtrol | VM_EXIT_HOST_ADDR_SPACE_SIZE; 

    return vmwrite(econtrol_final, VM_EXIT_CONTROLS);
}

int init_vm_execution_control_field(void){
    /*
    VM execution control further divided into following fields
        Pin-based (asynchronous) controls
        Processor-based (synchronous) controls
        Exception bitmap
        I/O bitmap addresses
        Timestamp Counter offset
        CR0/CR4 guest/host masks
        CR3 targets
        MSR Bitmaps
        Extended-Page-Table Pointer (EPTP) 
        Virtual-Processor Identifier (VPID) 
    */    

    
    //pin based controls 
    //we can put IA32_VMX_PINBASED_CTLS  values to pin based controls but we need to do and operation between first 32 bits to next 32 bits to get the supported value of that bit in pin based control.
    long unsigned int pcontrol;
    rdmsrl(MSR_IA32_VMX_PINBASED_CTLS, pcontrol);
    
    unsigned int pcontrol_final = (pcontrol & (pcontrol >> 32)); 
    int ret = vmwrite(pcontrol_final, PIN_BASED_VM_EXEC_CONTROLS);

    if(ret)
        return 1;

    //proc based control 
    //Similar to pin based control we can set proc based control using IA32_VMX_PROCBASED_CTLS.
    rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS, pcontrol);
    
    pcontrol_final = (pcontrol & (pcontrol >> 32)); 
    ret = vmwrite(pcontrol_final, PROC_BASED_VM_EXEC_CONTROLS);

    if(ret)
        return 1;

    //exception bitmap
    //setting this to 0 for now to ignore vmexit for guest exception
    ret = vmwrite(0, EXCEPTION_BITMAP);

    if(ret)
        return 1;

    return 0;
}

Trap init_vmcs(void){
    /*
    Section 24.3 
        
        The VMCS data are organized into six logical groups:
            • Guest-state area. Processor state is saved into the guest-state area on VM exits and loaded from there on
            VM entries.
            • Host-state area. Processor state is loaded from the host-state area on VM exits.
            • VM-execution control fields. These fields control processor behavior in VMX non-root operation. They
            determine in part the causes of VM exits.
            • VM-exit control fields. These fields control VM exits.
            • VM-entry control fields. These fields control VM entries.
            • VM-exit information fields. These fields receive information on VM exits and describe the cause and the
            nature of VM exits. On some processors, these fields are read-only.
    */
    if( init_vm_execution_control_field() )
        return TRAP_VMCS_INITIALIZATION_FAILED;

    if( init_exit_control_field() )
        return TRAP_VMCS_INITIALIZATION_FAILED;

    if( init_entry_control_field() )
        return TRAP_VMCS_INITIALIZATION_FAILED;

    return TRAP_OKAY;
}

Trap setup_vmcs(void) {
    
    //Section 24.1
    //A logical processor uses virtual-machine control data structures (VMCSs) while it nix operation.
    //Section 24.2
    //A VMCS region comprises up to 4-KBytes.
    long unsigned int temp;
    long unsigned int* vmcs_region = kzalloc(4096, GFP_KERNEL);
    if(vmcs_region == NULL)
        return TRAP_UNABLE_TO_ALLOCATE_MEM;

    long unsigned int physical_address = __pa(vmcs_region);

    //putting VMCS revision identifier into vmcs region
    rdmsrl(MSR_IA32_VMX_BASIC, temp);
    *(unsigned int*)vmcs_region = (unsigned int)temp;

    //You can only change VMCS Data if the VMCS is current and Active VMCS.
    //executing VMPTRLD to make it current and active VMCS
    uint8_t vmptrld_result = 0;

    asm volatile(
        "vmptrld %[pa]; setna %[vr]"
        : [vr] "=rm" (vmptrld_result)
        : [pa] "m" (physical_address)
        : "cc", "memory"
    );

    if(vmptrld_result)
        return  TRAP_VMPTRLD_FAILED;

    return TRAP_OKAY;
}

Trap enable_enter_vmx_operation(void) {
    
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
    
    if(vmxon_result)
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
    if(trap) {
        pr_err("ZaWarudo: ERROR: enable_enter_vmx_operation(): %d\n", trap);
        return 0;
    }pr_info("ZaWarudo: vmxon successful");

    trap = setup_vmcs();
    if(trap) {
        pr_err("ZaWarudo: ERROR: setup_vmcs(): %d\n", trap);
        return 0;
    }pr_info("ZaWarudo: VMCS setup successful");

    trap = init_vmcs();
        if(trap) {
        pr_err("ZaWarudo: ERROR: init_vmcs(): %d\n", trap);
        return 0;
    }pr_info("ZaWarudo: initailized VMCS");

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