//Account 패키지 : 어카운트 생성을 알아보는 코드 리뷰 :)



//경로 : go-ethereum/accounts/keystore/keystore.go/409



//** Accounts/KeyStore 패키지는 어카운트 키의 저장 디렉터리의 관리를 담당한다
//** NewAccount() 함수는 암호화를 하기 위한 키값을 변수 passphrase로 전달받고
//** storeNewKey() 함수를 호출한다

// NewAccount는 새 키를 생성하여 키 디렉토리에 저장
// 암호로 암호화
func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}

	// 캐시에 계정을 즉시 추가
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}






//경로 : go-ethereum/accounts/keystore/key.go /175



//** NewKey() 함수를 호출하여 임의의 문자열로 키를 생성하고 이를 저장한다
//** NewKey() 함수로 내부에서 crypto 패키지의 S256() 함수와 임의의 문자열을 매개변수로 ~

func storeNewKey(ks keyStore, rand io.Reader, auth string) (*Key, accounts.Account, error) {
	key, err := newKey(rand) // 키를 생성한다
	if err != nil {
		return nil, accounts.Account{}, err
	}
	a := accounts.Account{
		Address: key.Address,
		URL:     accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(key.Address))},
	}
	if err := ks.StoreKey(a.URL.Path, key, auth); err != nil { //키를 저장한다
		zeroKey(key.PrivateKey)
		return nil, a, err
	}
	return key, a, err
}







//경로 : go-ethereum/accounts/keystore/key.go /167



//** ecdsa.GenerateKey() 함수를 호출하여 임의의 256비트 개인키를 생성한다
//** 그리고 다시 이 개인키로 공개키를 생성하기 위해 ~
func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)  //개인키 생성
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil  //공개키 생성
}






//경로 : go-ethereum/accounts/keystore/key.go /133



//** newKeyFromECDSA() 함수를 호출한다
//** 이 함수 내에서 PubkeyToAddress() 함수를 호출하여 128비트 UUID를 생성한 후에
//** UUID와 바이트타입의 Address와 PrivateKey로 구성된 key 구조체의 포인터를 반환한다
func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id, err := uuid.NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Could not create random uuid: %v", err))
	}
	key := &Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),  //포인터 반환
		PrivateKey: privateKeyECDSA,
	}
	return key
}



//경로 : go-ethereum/crypto/crypto.go / 276



//** PubkeyToAddress() 함수는 Pubkey를 받은 후 Keccak256 암호 해시 한 뒤
//** BytesToAddress() 함수를 통해
//** 뒷부분 20 바이트만을 최종 어카운트로 잘라서 반환한다
func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}
