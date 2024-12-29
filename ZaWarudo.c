#include <linux/module.h> //Needed by all modules 
#include <linux/printk.h> //Needed for pr_info() 


static int __init entry(void) {

    pr_info("Hello world \n");
    
    return 0;
}


static void __exit exit(void)
{
    pr_info("Goodbye world \n");
}

module_init(entry);
module_exit(exit);


MODULE_LICENSE("GPL V3");
MODULE_AUTHOR("Deep");
MODULE_DESCRIPTION("ZaWarudo - A Simple Hypervisior ");
