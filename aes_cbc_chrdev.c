#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "tiny-AES-c/aes.h"

MODULE_LICENSE("GPL");

#define KEY_LEN 16 // Default set to 128bit for AES128, might be extented later
#define IV_LEN 16 // iv is 128bit for aes

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// Module parameters
static int encrypt = 1;
static char *key = "00112233445566778899aabbccddeeff"; // Default key

module_param(encrypt, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(encrypt, "1 for encryption, 0 for decryption");

module_param(key, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(key, "AES key in hex");

struct aesbuf{
    char * k_buf;
    size_t size;
    struct list_head list;
} aesbuf_st;

// Character device variables
struct aes_cbc_dev{
    dev_t dev_num;
    struct cdev cdev;
    struct class *dev_class;
    atomic_t device_in_use[2];
    int mode;
    unsigned char aes_key[KEY_LEN];
    unsigned char iv[IV_LEN];
    struct AES_ctx aesctx;

    struct aesbuf* in_list;
    struct aesbuf* out_list;
    spinlock_t in_spinlock;
    spinlock_t out_spinlock;

};

static struct aes_cbc_dev gDev;
// AES variables

static int aes_cbc_module_open(struct inode *inode, struct file *file);
static int aes_cbc_module_release(struct inode *inode, struct file *file);
static ssize_t aes_cbc_module_read(struct file *file, char __user *buf, size_t count, loff_t *offset);
static ssize_t aes_cbc_module_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);

static struct file_operations fops = {
    .open = aes_cbc_module_open,
    .release = aes_cbc_module_release,
    .read = aes_cbc_module_read,
    .write = aes_cbc_module_write,
};


static int aes_cbc_module_open(struct inode *inode, struct file *file) {
    int i;
    int minor = iminor(inode);      //Get the minor dev number indicate which file was opend
    // Check if the device is already open
    if(atomic_read(&gDev.device_in_use[minor])){
        pr_err("Device is in used by another process\n");
        return -EBUSY;  // Return an error code
    }
    // Set the device_in_use to indicate that the device is open
    atomic_inc(&gDev.device_in_use[minor]);
    pr_info("Device %s opened successfully\n", minor ? "vencrypt_ct" : "vencrypt_pt");
    // IV should be set to 0 only when the vencrypt_ct was opend in Decryption mode
    // and vecnrypt_pt was opend in Encryption mode
    if(((0 == encrypt) && (1 == minor)) ||
       ((1 == encrypt) && (0 == minor)) )
    {
        memset(gDev.iv, 0, IV_LEN);
        pr_info("Set IV to all zero when device opend!");
        pr_info("The IV set to [");
        for(i = 0; i < IV_LEN; i++)
            printk(KERN_CONT "%02x",gDev.iv[i]);
        printk(KERN_CONT "]");
        AES_init_ctx_iv(&gDev.aesctx, gDev.aes_key, gDev.iv);
    }
    return 0;
}


static int aes_cbc_module_release(struct inode *inode, struct file *file) {
    // Implement the release logic here
    int minor = iminor(inode);      //Get the minor dev number indicate which file was opend
    atomic_set(&gDev.device_in_use[minor], 0);
    pr_info("Device %s module_release\n", minor ? "vencrypt_ct" : "vencrypt_pt");
    return 0;
}

static ssize_t aes_cbc_module_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
    // Implement the read logic here
    int ret;
    ssize_t read_size = 0;
    struct aesbuf *cur_aesbuf = NULL;
    struct aesbuf *tmp_aesbuf = NULL;

    int minor = iminor(file->f_inode);      //Get the minor dev number indicate which file was opend
    pr_info("Try to read from %s\n", minor ? "vencrypt_ct" : "vencrypt_pt");
    if(((0 == encrypt) && (1 == minor)) ||
       ((1 == encrypt) && (0 == minor)) )
    {
        pr_err("Read from %s is not allowd when working in %s mode!\n",
            minor ? "vencrypt_ct" : "vencrypt_pt",
            encrypt ? "Encryption" : "Decryption");
        return -EACCES;
    }

    //Go through all the buffers need to be send out, and release them after sent to user
    list_for_each_entry_safe(cur_aesbuf, tmp_aesbuf, &(gDev.out_list->list),list)
    {
        ret = copy_to_user(buf + read_size, cur_aesbuf->k_buf, cur_aesbuf->size);
        if (ret != 0) {
            pr_err( "Failed to copy output data to user space\n");
        }
        read_size +=  cur_aesbuf->size ;
        pr_info("Read %ld data from current buffer list!", cur_aesbuf->size);
        kfree(cur_aesbuf->k_buf);
        cur_aesbuf->k_buf = NULL;
        cur_aesbuf->size = 0;
        spin_lock(&gDev.out_spinlock);
        list_del(&(cur_aesbuf->list));
        spin_unlock(&gDev.out_spinlock);
        kfree(cur_aesbuf);
        cur_aesbuf =  NULL;
    }
    return read_size;
}

static ssize_t aes_cbc_module_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    // Implement the write logic here
    int ret;
    char aes_buf[64] = {0};
    char * tmp_buf;
    struct aesbuf *tmp_aesbuf = NULL;

    int minor = iminor(file->f_inode);      //Get the minor dev number indicate which file was opend
    pr_info("Try to write from %s\n", minor ? "vencrypt_ct" : "vencrypt_pt");
    if(((0 == encrypt) && (0 == minor)) ||
       ((1 == encrypt) && (1 == minor)) )
    {
        pr_err("Write from %s is not allowd when working in %s mode!\n",
            minor ? "vencrypt_ct" : "vencrypt_pt",
            encrypt ? "Encryption" : "Decryption");
        return -EACCES;
    }


    if (count > PAGE_SIZE) {
        pr_err("Input data too large\n");
        return -ENOMEM;
    }

    tmp_buf = kmalloc(count, GFP_KERNEL);
    if (!tmp_buf) {
        pr_err("Failed to allocate memory\n");
        return -ENOMEM;
    }

    ret = copy_from_user(tmp_buf, buf, count);
    if (ret != 0) {
        pr_err( "Failed to copy input data from user space\n");
        kfree(tmp_buf);
        return -EFAULT;
    }
    
    tmp_aesbuf = kmalloc(sizeof(aesbuf_st),GFP_KERNEL);
    if (!tmp_aesbuf) {
        pr_err("Failed to allocate tmp_aesbuf\n");
        return -ENOMEM;
    }
    tmp_aesbuf->k_buf = tmp_buf;
    tmp_aesbuf->size = count;
    
    // Perform AES encryption on the input data here
    pr_info("Try to do AES for the first bloc, and Trasfer the input to output");
    memcpy(aes_buf, tmp_aesbuf->k_buf, tmp_aesbuf->size > 64 ? 64 : tmp_aesbuf->size);
    AES_CBC_encrypt_buffer(&gDev.aesctx, aes_buf, 64);
    memcpy(tmp_aesbuf->k_buf, aes_buf, tmp_aesbuf->size > 64 ? 64 : tmp_aesbuf->size);
    spin_lock(&gDev.out_spinlock);
    list_add_tail(&(tmp_aesbuf->list), &(gDev.out_list->list));
    spin_unlock(&gDev.out_spinlock);

    return count;
}

static int __init aes_cbc_module_init(void) {
    // Validate encrypt parameter
    int i;
    char tmp_key[KEY_LEN*2 +1] = {0};
    if (encrypt != 0 && encrypt != 1) {
        pr_err("Invalid value for 'encrypt' parameter. Use 0 or 1.\n");
        return -EINVAL;  // Return an error code
    }

    // Allocate a major number dynamically
    if (alloc_chrdev_region(&gDev.dev_num, 0, 2, "acs_cbc_module") < 0) {
        pr_err("Failed to allocate major number\n");
        return -ENOMEM;  // Return an error code
    }

    // Create a device class
    if ((gDev.dev_class = class_create(THIS_MODULE, "aes_cbc")) == NULL) {
        pr_err("Failed to create the device class\n");
        unregister_chrdev_region(gDev.dev_num, 2);
        return -ENOMEM;  // Return an error code
    }

    // Initialize the cdev structure and add it to the kernel
    cdev_init(&gDev.cdev, &fops);
    if (cdev_add(&gDev.cdev, gDev.dev_num, 2) == -1) {
        pr_err("Failed to add the character device\n");
        class_destroy(gDev.dev_class);
        unregister_chrdev_region(gDev.dev_num, 2);
        return -ENOMEM;  // Return an error code
    }

    //Check and conver the input key to 128bit for AES128
    // pr_info("Input key is [%s], length is %ld", key, strlen(key));
    if(strlen(key) < KEY_LEN*2){
        pr_warn("Input key is less than 128bit, adding 0 in the end!");
        for(i = 0; i < KEY_LEN*2; i ++)
            tmp_key[i] = '0';
        memcpy(tmp_key, key, strlen(key));
    }
    else{
        if(strlen(key) > KEY_LEN*2)
            pr_warn("Input key is more than 128bit, ingore the bits after first 128bit");
        memcpy(tmp_key, key,  KEY_LEN*2);
    }
    // Convert the hex key to binary
    if (hex2bin(gDev.aes_key, tmp_key,  sizeof(gDev.aes_key)) < 0) {
        pr_err("Failed to convert hex key to binary\n");
        cdev_del(&gDev.cdev);
        class_destroy(gDev.dev_class);
        unregister_chrdev_region(gDev.dev_num, 2);
        return -EINVAL;  // Return an error code
    }

    pr_info("The key set to [");
    for(i = 0; i < KEY_LEN; i++)
        printk(KERN_CONT "%02x",gDev.aes_key[i]);
    printk(KERN_CONT "]");

    // Create AES cipher handle

    // Create the device nodes
    device_create(gDev.dev_class, NULL, MKDEV(MAJOR(gDev.dev_num), 0), NULL, "vencrypt_pt");
    device_create(gDev.dev_class, NULL, MKDEV(MAJOR(gDev.dev_num), 1), NULL, "vencrypt_ct");

    // Init the atomic used flag to 0
    atomic_set(&gDev.device_in_use[0], 0);
    atomic_set(&gDev.device_in_use[1], 0);
    
    // Init the in & out buf_list and locks
    gDev.in_list = kmalloc(sizeof(aesbuf_st),GFP_KERNEL);
    if(NULL == gDev.in_list)
    {
        pr_err("Failed to allocate gDev.in_list\n");
        return -ENOMEM;  // Return an error code
    }
    INIT_LIST_HEAD(&(gDev.in_list->list));
    gDev.out_list = kmalloc(sizeof(aesbuf_st),GFP_KERNEL);
    if(NULL == gDev.out_list)
    {
        pr_err("Failed to allocate gDev.out_list\n");
        kfree(gDev.in_list);
        return -ENOMEM;  // Return an error code
    }
    INIT_LIST_HEAD(&(gDev.out_list->list));
    spin_lock_init(&gDev.in_spinlock);
    spin_lock_init(&gDev.out_spinlock);

    pr_info("ACS CBC Module Loaded in %s mode!\n", (encrypt ? "Encryption" : "Decryption"));
    return 0;
}

static void __exit aes_cbc_module_exit(void) {
    // Release resources
    kfree(gDev.in_list);
    kfree(gDev.out_list);
    device_destroy(gDev.dev_class, MKDEV(MAJOR(gDev.dev_num), 0));
    device_destroy(gDev.dev_class, MKDEV(MAJOR(gDev.dev_num), 1));
    class_destroy(gDev.dev_class);
    cdev_del(&gDev.cdev);
    unregister_chrdev_region(gDev.dev_num, 2);

    pr_info("ACS CBC Module Unloaded\n");
}

module_init(aes_cbc_module_init);
module_exit(aes_cbc_module_exit);
