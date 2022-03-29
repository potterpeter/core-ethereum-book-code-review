// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.

package accounts

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
	"golang.org/x/crypto/sha3"
)


// URL 필드에 의해 특정 위치에 있는 계정을 나타낸다
type Account struct {
	Address common.Address `json:"address"` // 키에서 파생된 이더리움 주소
	URL     URL            `json:"url"`     
}

const (
	MimetypeDataWithValidator = "data/validator"
	MimetypeTypedData         = "data/typed"
	MimetypeClique            = "application/x-clique-header"
	MimetypeTextPlain         = "text/plain"
)


// wallet은 하나의 시드로부터 파생된 한 개 이상의 계정들을 담을 수 있는 소프트웨어 또는 하드웨어 지갑을 말한다
type Wallet interface {

	//URL은 이 지갑에 대한 경로를 검색한다
	URL() URL

	//Status는 지갑의 현재상태에서 사용자를 돕기 위한 텍스트 상태를 반환한다
	//또한 지갑에서 일어날 수 있는 오류가 나타났을 때 오류를 반환한다
	Status() (string, error)

	//Open은 지갑 인스턴스에 대한 접근을 초기화한다

	//passphrase 파라미터는 특정 지갑 인스턴스 구현에 사용되거나, 혹은 사용 안 될 수도 있다
	//다른 백엔드 환경에서도 균일한 지갑 상태를 유지하기 위해 비밀번호가 없는 오픈 방식은 없다
	Open(passphrase string) error

	//Close는 열려있는 지갑 인스턴스의 어떤 리소스도 모두 해제한다
	Close() error

	// Accounts는 지갑이 현재 인식하고 있는 서명 계정 목록을 검색한다 
	// 계층적 결정론적 지갑의 경우, 리스트는 완전하지 않고 계정 파생 과정에서 명시적으로 고정된 계정만 포함
	Accounts() []Account

	// Contains는 이 특정 지갑의 일부인지 여부를 반환
	Contains(account Account) bool


	Derive(path DerivationPath, pin bool) (Account, error)

	// SelfDerive는 지갑이 제로계정 이외를 검출하여 
	//추적 대상 계정 목록에 자동으로 추가하는 기본 계정 파생 경로를 설정
	SelfDerive(bases []DerivationPath, chain ethereum.ChainStateReader)

	// SignData는 지갑에 주어진 데이터의 해시 서명을 요청
	SignData(account Account, mimeType string, data []byte) ([]byte, error)


	SignDataWithPassphrase(account Account, passphrase, mimeType string, data []byte) ([]byte, error)

	// SignText는 선두에 있는 특정 데이터의 해시에 서명하도록 지갑 요청
	// 이 메서드는 v 0 또는 1과 함께 '정식' 형식 서명 반환
	SignText(account Account, text []byte) ([]byte, error)

	SignTextWithPassphrase(account Account, passphrase string, hash []byte) ([]byte, error)

	// SignTx는 지갑에 주어진 트랜잭션에 서명하도록 요청
	SignTx(account Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)

	SignTxWithPassphrase(account Account, passphrase string, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}


//Backend는 트랜잭션에 서명할 수 있는 계정들을 가지고 있는 '지갑 공급자'이다
type Backend interface {
	
	// 지갑은 Backend가 현재 인식하고 있는 지갑 목록을 가져온다
	Wallets() []Wallet

	// Subscribe는 백엔드가 지갑의 도착이나 출발을 감지했을 때, 알림을 주는 비동기 서브스크립트를 만든다
	Subscribe(sink chan<- WalletEvent) event.Subscription
}

// TextHash는 서명을 안전하게 계산할 수 있게 도와주는 함수
func TextHash(data []byte) []byte {
	hash, _ := TextAndHash(data)
	return hash
}

func TextAndHash(data []byte) ([]byte, string) {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), string(data))
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(msg))
	return hasher.Sum(nil), msg
}


type WalletEventType int

const (
	// WalletArrived는 새 지갑에서 USB 또는 키스토어의 파일시스템 이벤트가 감지되면 실행된다
	WalletArrived WalletEventType = iota

	WalletOpened

	WalletDropped
)

// WalletEvent는 계정 백엔드에서 지갑이 도착하거나 출발이 감지될 때 실행된다 
type WalletEvent struct {
	Wallet Wallet          // Wallet 인스턴스 출발 또는 도착
	Kind   WalletEventType // 발생한 이벤트 유형
}