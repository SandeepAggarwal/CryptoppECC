//
//  ViewController.m
//  cryptoppdemo
//
//  Created by utogaria on 2015-08-11.
//  Copyright (c) 2015 utogaria. All rights reserved.
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
