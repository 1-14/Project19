# Project-forge-a-signature-to-pretend-that-you-are-Satoshi
ECDSA未检查签名邮件时，伪造合法签名使得你可以被认为是Satoshi

## 椭圆曲线数字签名算法

简单来说，与DSA本质上区别不大，在原DSA生成r的地方引入了椭圆曲线以及一些其他参数的变化

公私钥的生成

私钥

    随机取一个在 ( 1 ， n − 1 ) 区间上的整数da作为私钥
    
    这里的n是选取椭圆曲线上的order，也就是椭圆曲线加密方程的模数，之后提到的n都是这个

公钥

    Q = da ∗ G ，其中Q是公钥，也就是说这里公钥是通过私钥生成的，而G是椭圆曲线上的基点。
    
    注意这个等式的乘法不是普通的乘法，是椭圆曲线加密中的乘法

**数字签名sign**

    生成一个临时密钥k 

    计算 P = k ∗ G其中P是椭圆曲线上的一个点

    取P点的x坐标， r ≡ x (mod n) 

    使用SHA1函数计算message的哈希值，使用H(m)表示，注意这个哈希值需要转换为数值型

    s ≡ k^(-1)∗ (H(m)+dA∗r)(mod n) 

而(r,s)即为sign算法的输出结果

**代码运行指导**

运行代码之前需要在pycharm中安装ecdsa与hashlib两个库文件进行调用，才能正常运行！

## 关键代码展示

### 1. ECDSA——sign

```
def Ecdsa_Sign(m, n, G, d,k):
    e = hash(m)
    R = Multiply(k, G)
    r = R[0] % n
    s = (Gcd(k, n) * (e + d * r)) % n
    return r, s
```

### 2. ECDSA——vrfy

```
def Ecdsa_Verify(m, n, G, r, s, P):
    e = hash(m)
    w = Gcd(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = Add(Multiply(v1, G), Multiply(v2, P))
    if (w == 0):
        print('false')
        return False
    else:
        if (w[0] % n == r):
            print('true')
            return True
        else:
            print('false')
            return False
```

### 3. 泄露k导致密钥泄露

```
def k_Leaking(r,n,k,s,m):
    r_reverse=Gcd(r,n)
    e=hash(m)
    d=r_reverse * (k*s-e)%n
    return d
```

### 4. 重用k导致密钥泄露

```
def k_Reuse(r1,s1,m1,r2,s2,m2,n):
    e1=hash(m1)
    e2=hash(m2)
    d=((s1 * e2 - s2 * e1) * Gcd((s2 * r1 - s1 * r1), n)) % n
    return d
```

### 5. 使用相同k，可互相计算密钥

```
def Use_the_Same_k(s1,m1,s2,m2,r,d1,d2,n):
    e1=hash(m1)
    e2=hash(m2)
    d2_1 = ((s2 * e1 - s1 * e2 + s2 * r * d1) * Gcd(s1 * r, n)) % n
    d1_1 = ((s1 * e2 - s2 * e1 + s1 * r * d2) * Gcd(s2 * r, n)) % n
    if(d2==d2_1 and d1_1==d1):
        print("密钥合法计算成功！")
        return 1
    else:
        print("密钥非法计算错误！")
        return 0
```

### 6.不验证m的验证算法

```
def Verify_without_m(e, n, G, r, s, P):
    w = Gcd(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = Add(Multiply(v1, G), Multiply(v2, P))
    if (w == 0):
        print('false')
        return False
    else:
        if (w[0] % n == r):
            print('true')
            return True
        else:
            print('false')
            return False
```

### 7.伪装攻击者身份，被认定为Satoshi

```
def Pretend(r, s, n, G, P):
    u = random.randrange(1, n - 1)
    v = random.randrange(1, n - 1)
    r1 = Add(Multiply(u, G), Multiply(v, P))[0]
    e1 = (r1 * u * Gcd(v, n)) % n
    s1 = (r1 * Gcd(v, n)) % n
    Verify_without_m(e1, n, G, r1, s1, P)
```

### 8.Schnorr_Sign签名

```
def Schnorr_Sign(m, n, G, d,k):
    R = Multiply(k, G)
    e = hash(str(R[0]) + m)
    s = (k + e * d) % n
    return R, s
```

### 9.Schnorr_Sign签名、ecdsa签名使用相同的d，k，导致密钥泄露

```
def Schnorr_and_ECDSA(r1, s1, R, s2, m, n):
    e1 = int(hash(m))
    e2 = int(hash(str(R[0]) + m))
    d = ((s1 * s2 - e1) * Gcd((s1 * e2 + r1), n)) % n
    return d
```


## 测试运行结果截图

![image](https://github.com/1-14/Project19/blob/main/2.png)
