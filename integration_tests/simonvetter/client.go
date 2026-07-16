package main

import (
	"fmt"
	"os"
	"time"

	"github.com/simonvetter/modbus"
)

func runTests(client *modbus.ModbusClient) error {
	fmt.Println("1. Testing Read/Write Coils...")
	// Write single coil
	err := client.WriteCoil(0, true)
	if err != nil {
		return fmt.Errorf("WriteCoil(0, true) failed: %w", err)
	}

	coils, err := client.ReadCoils(0, 1)
	if err != nil {
		return fmt.Errorf("ReadCoils(0, 1) failed: %w", err)
	}
	if len(coils) != 1 || !coils[0] {
		return fmt.Errorf("unexpected coil 0 value: %v", coils)
	}

	// Write multiple coils
	err = client.WriteCoils(5, []bool{true, false, true, true})
	if err != nil {
		return fmt.Errorf("WriteCoils(5) failed: %w", err)
	}

	coils, err = client.ReadCoils(5, 4)
	if err != nil {
		return fmt.Errorf("ReadCoils(5, 4) failed: %w", err)
	}
	expectedCoils := []bool{true, false, true, true}
	for i, v := range expectedCoils {
		if coils[i] != v {
			return fmt.Errorf("unexpected coil at index %d: got %v, expected %v", i, coils[i], v)
		}
	}

	fmt.Println("2. Testing Read Discrete Inputs...")
	discretes, err := client.ReadDiscreteInputs(0, 4)
	if err != nil {
		return fmt.Errorf("ReadDiscreteInputs(0, 4) failed: %w", err)
	}
	expectedDiscretes := []bool{true, false, true, false}
	for i, v := range expectedDiscretes {
		if discretes[i] != v {
			return fmt.Errorf("unexpected discrete input at index %d: got %v, expected %v", i, discretes[i], v)
		}
	}

	fmt.Println("3. Testing Holding Registers...")
	// Write single register
	err = client.WriteRegister(10, 42)
	if err != nil {
		return fmt.Errorf("WriteRegister(10, 42) failed: %w", err)
	}

	regs, err := client.ReadRegisters(10, 1, modbus.HOLDING_REGISTER)
	if err != nil {
		return fmt.Errorf("ReadRegisters(10, 1) failed: %w", err)
	}
	if len(regs) != 1 || regs[0] != 42 {
		return fmt.Errorf("unexpected holding register 10 value: %v", regs)
	}

	// Write multiple registers
	err = client.WriteRegisters(20, []uint16{100, 200, 300})
	if err != nil {
		return fmt.Errorf("WriteRegisters(20) failed: %w", err)
	}

	regs, err = client.ReadRegisters(20, 3, modbus.HOLDING_REGISTER)
	if err != nil {
		return fmt.Errorf("ReadRegisters(20, 3) failed: %w", err)
	}
	expectedRegs := []uint16{100, 200, 300}
	for i, v := range expectedRegs {
		if regs[i] != v {
			return fmt.Errorf("unexpected holding register at index %d: got %v, expected %v", i, regs[i], v)
		}
	}

	fmt.Println("4. Testing Input Registers...")
	regs, err = client.ReadRegisters(0, 2, modbus.INPUT_REGISTER)
	if err != nil {
		return fmt.Errorf("ReadRegisters(0, 2, INPUT) failed: %w", err)
	}
	expectedInputs := []uint16{1234, 5678}
	for i, v := range expectedInputs {
		if regs[i] != v {
			return fmt.Errorf("unexpected input register at index %d: got %v, expected %v", i, regs[i], v)
		}
	}

	return nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: client <url> <slave_id>")
		os.Exit(1)
	}

	url := os.Args[1]
	slaveIdStr := os.Args[2]
	var slaveId uint8
	_, err := fmt.Sscanf(slaveIdStr, "%d", &slaveId)
	if err != nil {
		fmt.Printf("Invalid slave_id: %s\n", slaveIdStr)
		os.Exit(1)
	}

	client, err := modbus.NewClient(&modbus.ClientConfiguration{
		URL:      url,
		Timeout:  2 * time.Second,
		Speed:    19200,
		DataBits: 8,
		Parity:   modbus.PARITY_NONE,
		StopBits: 1,
	})
	if err != nil {
		fmt.Printf("modbus.NewClient failed: %v\n", err)
		os.Exit(1)
	}

	err = client.SetUnitId(slaveId)
	if err != nil {
		fmt.Printf("SetUnitId failed: %v\n", err)
		os.Exit(1)
	}

	err = client.Open()
	if err != nil {
		fmt.Printf("client.Open failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	err = runTests(client)
	if err != nil {
		fmt.Printf("Tests failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("ALL TESTS PASSED")
}
