//
//  ViewController.m
//  cryptoppdemo
//
//Created by Sandeep Aggarwal on 14/06/15.
//

#import "ViewController.h"
#import "CryptoppECC.h"
#import "CryptoppECDSA.h"

//new one

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    CryptoppECC* ecc=[[CryptoppECC alloc] init];
    [ecc randomKeysEncryptDecrypt];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
