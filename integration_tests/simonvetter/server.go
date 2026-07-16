package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/simonvetter/modbus"
)

type DeviceHandler struct {
	lock             sync.RWMutex
	coils            [100]bool
	discreteInputs   [100]bool
	holdingRegisters [100]uint16
	inputRegisters   [100]uint16
}

func (h *DeviceHandler) HandleCoils(req *modbus.CoilsRequest) (res []bool, err error) {
	if req.UnitId != 1 {
		err = modbus.ErrIllegalFunction
		return
	}
	if int(req.Addr)+int(req.Quantity) > len(h.coils) {
		err = modbus.ErrIllegalDataAddress
		return
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	for i := 0; i < int(req.Quantity); i++ {
		addr := int(req.Addr) + i
		if req.IsWrite {
			h.coils[addr] = req.Args[i]
		}
		res = append(res, h.coils[addr])
	}
	return
}

func (h *DeviceHandler) HandleDiscreteInputs(req *modbus.DiscreteInputsRequest) (res []bool, err error) {
	if req.UnitId != 1 {
		err = modbus.ErrIllegalFunction
		return
	}
	if int(req.Addr)+int(req.Quantity) > len(h.discreteInputs) {
		err = modbus.ErrIllegalDataAddress
		return
	}

	h.lock.RLock()
	defer h.lock.RUnlock()

	for i := 0; i < int(req.Quantity); i++ {
		addr := int(req.Addr) + i
		res = append(res, h.discreteInputs[addr])
	}
	return
}

func (h *DeviceHandler) HandleHoldingRegisters(req *modbus.HoldingRegistersRequest) (res []uint16, err error) {
	if req.UnitId != 1 {
		err = modbus.ErrIllegalFunction
		return
	}
	if int(req.Addr)+int(req.Quantity) > len(h.holdingRegisters) {
		err = modbus.ErrIllegalDataAddress
		return
	}

	h.lock.Lock()
	defer h.lock.Unlock()

	for i := 0; i < int(req.Quantity); i++ {
		addr := int(req.Addr) + i
		if req.IsWrite {
			h.holdingRegisters[addr] = req.Args[i]
		}
		res = append(res, h.holdingRegisters[addr])
	}
	return
}

func (h *DeviceHandler) HandleInputRegisters(req *modbus.InputRegistersRequest) (res []uint16, err error) {
	if req.UnitId != 1 {
		err = modbus.ErrIllegalFunction
		return
	}
	if int(req.Addr)+int(req.Quantity) > len(h.inputRegisters) {
		err = modbus.ErrIllegalDataAddress
		return
	}

	h.lock.RLock()
	defer h.lock.RUnlock()

	for i := 0; i < int(req.Quantity); i++ {
		addr := int(req.Addr) + i
		res = append(res, h.inputRegisters[addr])
	}
	return
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: server <listen_url>")
		os.Exit(1)
	}

	url := os.Args[1]

	handler := &DeviceHandler{}
	// Initialize default values to match Python client expectations
	handler.coils[0] = true
	handler.discreteInputs[0] = true
	handler.discreteInputs[1] = false
	handler.discreteInputs[2] = true
	handler.discreteInputs[3] = false
	handler.inputRegisters[0] = 1234
	handler.inputRegisters[1] = 5678

	server, err := modbus.NewServer(&modbus.ServerConfiguration{
		URL:        url,
		Timeout:    30 * time.Second,
		MaxClients: 10,
	}, handler)
	if err != nil {
		fmt.Printf("Failed to create server: %v\n", err)
		os.Exit(1)
	}

	err = server.Start()
	if err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Server listening on %s...\n", url)
	select {}
}
