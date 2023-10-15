#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/random.h>

MODULE_LICENSE("GPL");

// Module parameters
static int encrypt = 1;
static char *key = "00112233445566778899aabbccddeeff"; // Default key

module_param(encrypt, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(encrypt, "1 for encryption, 0 for decryption");

module_param(key, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(key, "AES key in hex");

// Character device variables
static dev_t dev_num;
static struct cdev cdev;
static struct class *dev_class;
static DEFINE_SEMAPHORE(device_sem);

// AES variables
static char aes_key[16];

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
    if (down_interruptible(&device_sem)) {
        pr_err("Failed to acquire semaphore\n");
        return -ERESTARTSYS;  // Return an error code
    }

    // Check if the device is already open
    if (file->private_data) {
        pr_err("Device already opened by another process\n");
        up(&device_sem);
        return -EBUSY;  // Return an error code
    }

    // Set the private data to indicate that the device is open
    file->private_data = (void *)1;

    pr_info("Device opened successfully\n");
    return 0;
}


static int aes_cbc_module_release(struct inode *inode, struct file *file) {
    // Implement the release logic here
    pr_info("aes_cbc_module_release\n");

    return 0;
}

static ssize_t aes_cbc_module_read(struct file *file, char __user *buf, size_t count, loff_t *offset) {
    // Implement the read logic here
    pr_info("aes_cbc_module_read\n");

    return 0;
}

static ssize_t aes_cbc_module_write(struct file *file, const char __user *buf, size_t count, loff_t *offset) {
    // Implement the write logic here
    pr_info("aes_cbc_module_write\n");

    return 0;
}

static int __init aes_cbc_module_init(void) {
    // Validate encrypt parameter
    if (encrypt != 0 && encrypt != 1) {
        pr_err("Invalid value for 'encrypt' parameter. Use 0 or 1.\n");
        return -EINVAL;  // Return an error code
    }


    // Allocate a major number dynamically
    if (alloc_chrdev_region(&dev_num, 0, 2, "acs_cbc_module") < 0) {
        pr_err("Failed to allocate major number\n");
        return -ENOMEM;  // Return an error code
    }

    // Create a device class
    if ((dev_class = class_create(THIS_MODULE, "aes_cbc")) == NULL) {
        pr_err("Failed to create the device class\n");
        unregister_chrdev_region(dev_num, 2);
        return -ENOMEM;  // Return an error code
    }

    // Initialize the cdev structure and add it to the kernel
    cdev_init(&cdev, &fops);
    if (cdev_add(&cdev, dev_num, 2) == -1) {
        pr_err("Failed to add the character device\n");
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 2);
        return -ENOMEM;  // Return an error code
    }

    // Convert the hex key to binary
    if (hex2bin(aes_key, key, sizeof(aes_key)) < 0) {
        pr_err("Failed to convert hex key to binary\n");
        cdev_del(&cdev);
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 2);
        return -EINVAL;  // Return an error code
    }

    // Create AES cipher handle

    // Create the device nodes
    device_create(dev_class, NULL, MKDEV(MAJOR(dev_num), 0), NULL, "vencrypt_pt");
    device_create(dev_class, NULL, MKDEV(MAJOR(dev_num), 1), NULL, "vencrypt_ct");

    pr_info("ACS CBC Module Loaded in %s mode!\n", (encrypt ? "Encryption" : "Decryption"));
    return 0;
}

static void __exit aes_cbc_module_exit(void) {
    // Release resources
    device_destroy(dev_class, MKDEV(MAJOR(dev_num), 0));
    device_destroy(dev_class, MKDEV(MAJOR(dev_num), 1));
    class_destroy(dev_class);
    cdev_del(&cdev);
    unregister_chrdev_region(dev_num, 2);

    pr_info("ACS CBC Module Unloaded\n");
}

module_init(aes_cbc_module_init);
module_exit(aes_cbc_module_exit);
