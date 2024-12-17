from Assembler import Assembler

class SimpleComputer:
    def __init__(self):
        # Memory: A dictionary where the key is a 32-bit address (hex), and the value is 4 cells (each 8 bits)
        self.memory = {}

        # Registers: 32 registers, each 32 bits
        self.registers = [0] * 32

        # Instruction pointer, initialized to 0
        self.instruction_pointer = 0

        # Create an instance of the Assembler
        self.assembler = Assembler()

        # BTB and BPB entries
        self.branch_plugin = {
            "BTB": {},  # Branch Target Buffer: {instruction_address: target_address}
            "BPB": {}   # Branch Prediction Buffer: {instruction_address: 2-bit history (00 to 11)}
        }

        # JGE lock
        self.jge_lock = False

    def _check_address(self, address):
        """Check if the address is a valid 32-bit hex address."""
        if not (0 <= address <= 0xFFFFFFFF):
            raise ValueError("Address must be a 32-bit hexadecimal value (0x00000000 to 0xFFFFFFFF).")

    def load(self, register_idx, address):
        """
        Load a 32-bit value from memory into the specified register.
        
        :param register_idx: The index of the register (0-31).
        :param address: The starting memory address as a hexadecimal number (e.g., 0x100).
        """
        # Read 4 consecutive 8-bit values from memory as strings
        byte1 = self.memory.get(address, "00000000")         # Memory[address]
        byte2 = self.memory.get(address + 1, "00000000")     # Memory[address + 1]
        byte3 = self.memory.get(address + 2, "00000000")     # Memory[address + 2]
        byte4 = self.memory.get(address + 3, "00000000")     # Memory[address + 3]

        # Concatenate the bytes into a single 32-bit binary string
        binary_string = byte1 + byte2 + byte3 + byte4

        # Convert the binary string to an integer
        value = int(binary_string, 2)

        # Store the 32-bit value in the specified register
        self.registers[register_idx] = value

    def store(self, register_idx, address):
        """
        Store the value from the specified register into memory at the given address.
        
        Parameters:
        register_idx (int): The index of the register (0 to 31).
        address (int): The starting memory address to store the data (in decimal).
        """
        # Get the value from the specified register
        register_value = self.registers[register_idx]
        
        # Convert to a 32-bit binary string
        binary_value = f"{register_value:032b}"
        
        # Split the binary string into four 8-bit segments
        bytes_to_store = [binary_value[i:i+8] for i in range(0, 32, 8)]
        
        # Store each byte in the respective memory addresses
        for i, byte in enumerate(bytes_to_store):
            self.memory[address + i] = byte  # Store the 8-bit binary string

    def add(self, dest_idx, src1_idx, src2_idx):
        """Add the values of two source registers and store the result in a destination register."""
        if all(0 <= idx < len(self.registers) for idx in [dest_idx, src1_idx, src2_idx]):
            self.registers[dest_idx] = self.registers[src1_idx] + self.registers[src2_idx]
        else:
            raise ValueError("Register index out of bounds.")
    
    def print_registers(self):
        """
        Print the current values of all 32 registers in 32-bit binary format.
        """
        for i in range(32):
            register_value = self.registers[i]
            print(type(register_value))
            # Format the value as a 32-bit binary string and print it
            print(f"r{i}: {format(register_value, '032b')}")

    def translate_print_assembly(self, instructions):
        """Translate assembly instructions and run them on the computer."""
        binary_instructions = self.assembler.translate_assembly(instructions)
        self.assembler.print_binary_instructions(binary_instructions)

    def initialize_memory(self, start_address, data):
        """
        Initialize memory starting from start_address with the provided list of 32-bit binary numbers (data).
        Each 32-bit number is split into 4 bytes (8-bit), and each byte is written to a consecutive memory address.
        
        :param start_address: The memory address where writing begins (integer).
        :param data: A list of 32-bit binary strings.
        """
        current_address = start_address
        for word in data:
            if len(word) != 32 or not all(c in '01' for c in word):
                raise ValueError("Each data element must be a 32-bit binary string.")

            # Split the 32-bit binary string into four 8-bit segments
            byte1 = word[0:8]   # First 8 bits
            byte2 = word[8:16]  # Next 8 bits
            byte3 = word[16:24] # Next 8 bits
            byte4 = word[24:32] # Last 8 bits
            
            # Write each byte to memory at consecutive addresses
            self.memory[current_address] = byte1
            self.memory[current_address + 1] = byte2
            self.memory[current_address + 2] = byte3
            self.memory[current_address + 3] = byte4

            # Move to the next word (next 4 addresses)
            current_address += 4

    def print_memory(self, start_address, length):
        """
        Print the memory content from start_address to start_address + length in 8-bit binary format.
        
        :param start_address: The starting address in hexadecimal (string format, e.g., "0x100").
        :param length: The number of memory cells to print, in hexadecimal (string format, e.g., "0x10").
        """
        # Convert the start_address and length from hexadecimal string to integer
        start_address = int(start_address, 16)
        length = int(length, 16)

        # Print the memory content from start_address to start_address + length
        for address in range(start_address, start_address + length):
            if address in self.memory:
                # Print the 8-bit binary content of the memory cell
                print(f"Memory[{hex(address)}] = {self.memory[address]}")
            else:
                # Print 8 zeros if the memory cell is empty/uninitialized
                print(f"Memory[{hex(address)}] = 00000000")

    def plugins_BTB_BPB(self, instruction_address):
        """
        Simulate the functionality of BTB and BPB.
        Args:
            instruction_address: The current instruction address (without base).
        Returns:
            (should_jump: bool, target_address: int or None): 
            A tuple indicating whether to jump and the predicted target address.
        """
        # Default: no jump
        should_jump = False
        target_address = None

        # Check BTB and BPB for the current instruction address
        btb_entry = self.branch_plugin["BTB"].get(instruction_address)
        bpb_entry = self.branch_plugin["BPB"].get(instruction_address, 0b00)  # Default to "strongly not taken"

        # BPB: Predict based on the 2-bit history
        if bpb_entry in {0b10, 0b11}:  # Weakly or strongly taken
            should_jump = True
            target_address = btb_entry  # Use BTB if available, else None

        return should_jump, target_address

    def update_branch_plugin(self, instruction_address, actual_taken, target_address):
        """
        Update BTB and BPB entries based on the actual branch result.
        Args:
            instruction_address: The instruction address (without base).
            actual_taken: Whether the branch was actually taken.
            target_address: The actual target address if taken, else None.
        """
        # Update BPB: Adjust the 2-bit history
        current_bpb = self.branch_plugin["BPB"].get(instruction_address, 0b00)

        if actual_taken:
            # Increment history towards "taken" (10 or 11)
            if current_bpb < 0b11:
                current_bpb += 1
        else:
            # Decrement history towards "not taken" (00 or 01)
            if current_bpb > 0b00:
                current_bpb -= 1

        self.branch_plugin["BPB"][instruction_address] = current_bpb

        # Update BTB: If branch was taken, record the target address
        if actual_taken and target_address is not None:
            self.branch_plugin["BTB"][instruction_address] = target_address
        elif not actual_taken and instruction_address in self.branch_plugin["BTB"]:
            # Remove BTB entry if branch is not taken
            del self.branch_plugin["BTB"][instruction_address]

    def run_assembly(self, instructions, start_address):
        """
        Translate assembly instructions, convert to binary, and write to memory starting at start_address.
        """
        binary_instructions = self.assembler.translate_assembly(instructions)

        # Convert binary instructions to 32-bit binary strings
        binary_strings = [f"{instruction:032b}" for instruction in binary_instructions]

        # Use initialize_memory to write the binary instructions into memory
        self.initialize_memory(start_address, binary_strings)

        # Set up registers
        self.registers[31] = start_address  # Base address in r31
        self.registers[30] = 0  # Program Counter (PC) in r30
        self.registers[28] = 0  # Data register (r28)
        self.registers[29] = 0  # Instruction register (r29)

        # Execute the program
        while self.registers[30] < len(binary_strings) * 4:  # Check PC within instruction range
            # Fetch the instruction from memory
            while(self.jge_lock == True):  # What for getting JGE actual_taken
                tmp = 1
            pc_address = self.registers[31] + self.registers[30]  # Base + PC
            self.load(29, pc_address)  # Load instruction into r29

            # Decode the instruction
            instruction = self.registers[29]

            opcode = (instruction >> 27) & 0x1F  # Extract the opcode
            operands = [
                (instruction >> 18) & 0x1FF,  # First operand (9 bits)
                (instruction >> 9) & 0x1FF,   # Second operand (9 bits)
                instruction & 0x1FF            # Third operand (9 bits)
            ]

            # Execute based on opcode
            print(f"Now PC: {self.registers[30]}, is going to be executed.")
            if opcode == 0b00001:  # LOAD
                src_address = operands[1]  # Memory address from the first operand
                self.load(28, src_address)  # Load data into data register (r28)
                dest_reg_idx = operands[0] & 0x1F  # Get register index from the second operand (low 5 bits)
                self.registers[dest_reg_idx] = self.registers[28]  # Move data to destination register
            elif opcode == 0b00010:  # STORE
                src_reg_idx = operands[0] & 0x1F  # Get register index from the first operand
                self.registers[28] = self.registers[src_reg_idx]
                self.store(28, operands[1])  # Store from data register to memory
            elif opcode == 0b00011:  # ADD
                dest_reg_idx = operands[0] & 0x1F  # Get register index from the first operand
                src_reg_idx1 = operands[1] & 0x1F  # Get register index from the second operand
                src_reg_idx2 = operands[2] & 0x1F  # Get register index from the third operand
                self.add(dest_reg_idx, src_reg_idx1, src_reg_idx2)  # Add registers
            elif opcode == 0b00100:  # JGE
                # Simulate BTB and BPB prediction
                instruction_address = self.registers[30]  # PC without base
                predicted_jump, predicted_target = self.plugins_BTB_BPB(instruction_address)

                # Apply prediction
                if predicted_jump and predicted_target is not None:
                    self.registers[30] = predicted_target
                    #continue  # Skip actual execution if predicted jump is taken
                
                self.jge_lock = True
                reg1_idx = operands[0] & 0x1F
                reg2_idx = operands[1] & 0x1F
                target_address = operands[2]

                # Execute the actual branch condition
                actual_taken = self.registers[reg1_idx] >= self.registers[reg2_idx]

                if actual_taken:
                    self.registers[30] = target_address
                    # Update branch plugin with actual results
                    self.update_branch_plugin(instruction_address, actual_taken, target_address)
                    self.jge_lock = False
                    continue  # Skip PC increment

                # Update branch plugin with actual results (not taken)
                self.update_branch_plugin(instruction_address, actual_taken, None)
                self.jge_lock = False
            # Simple JGE
            """
            elif opcode == 0b00100:  # JGE
                reg1_idx = operands[0] & 0x1F
                reg2_idx = operands[1] & 0x1F
                target_address = operands[2]
                if self.registers[reg1_idx] >= self.registers[reg2_idx]:
                    self.registers[30] = target_address
                    #print(f"hack: JGE pc: {self.registers[30]}")
                    continue  # Skip PC increment
            """

            # Increment the Program Counter (PC)
            self.registers[30] += 4  # Move to the next instruction

def demo_test_assembler():
    computer = SimpleComputer()

    instructions = [
        "LOAD r1, #0x00",
        "LOAD r2, #1",
        "ADD r3, r1, r2",
        "STORE r3, #0x03"
    ]

    # Translate and print the assembly instructions
    computer.translate_print_assembly(instructions)

def demo_test_run_assembly_command():
    computer = SimpleComputer()

    # Preload two 32-bit data values into memory
    data_to_load = [
        "00000000000000000000000000001111",   # Example data at memory address 0xa7 (15 in decimal)
        "00000000000000000000000000000001",   # Example data at memory address 0x1 (1 in decimal)
        "00000000000000000000000000010110"    # Example data at memory address 0x11 (18 in decimal)
    ]

    # Initialize memory at addresses 0xa7 and 0x1
    computer.initialize_memory(0xA7, [data_to_load[0]])  # Memory address 0xa7
    computer.initialize_memory(0x1, [data_to_load[1]])   # Memory address 0x1
    computer.initialize_memory(0x11, [data_to_load[2]])  # Memory address 0x11

    # Assembly program that will load, add, and store the result
    '''
    instructions = [
        "LOAD r1, #0xa7",   # Load memory at hex address 0xa7 into register 1
        "LOAD r2, #1",      # Load memory at decimal address 1 into register 2
        "ADD r3, r1, r2",   # Add values in r1 and r2, store result in r3
        "STORE r3, #0xb0"   # Store value from r3 into memory address 0xb0
    ]
    '''

    # Assembly program that will execute a loop, every round do 3 "Add-one" instructions. One “Add-one” instruction will be definitely skipped by JGE.
    instructions = [
        "LOAD r1, #0xa7",       # Load memory at hex address 0xa7 into register 1
        "LOAD r2, #1",          # Load memory at decimal address 1 into register 2
        "ADD r3, r1, r2",       # Add values in r1 and r2, store result in r3
        "JGE r2, r2, #0x14",    # Skip one ADD instruction, r2 is equal to r2, so this is a definite skip
        "ADD r3, r3, r2",       # Add 1
        "ADD r3, r3, r2",       # Add 1
        "ADD r3, r3, r2",       # Add 1
        "STORE r3, #0xa7",      # Store value from r3 into memory address 0xb0
        "LOAD r4, #0x11",       # Load the loop end flag
        "JGE r4, r3, #0x0"      # If r3 is still less than loop end flag, go back to take 3 "Add-One" instruction.
    ]

    # Set start address for program in memory
    start_address = 0x10000000  # Example start address

    # Show all binary machine code of assembly instrucitons
    print("======Machine Codes======")
    computer.translate_print_assembly(instructions)
    print("===End of machine Codes===")

    # Run the assembly instructions with the given start address
    computer.run_assembly(instructions, start_address)

    # Print memory content where the result is expected (0xb0)
    print("======Result======")
    computer.print_memory("0x000000A7", "0x4")
    print("===End of Result===")

    # Print final register values for verification
    print("=====Registers for verification=====")
    for i in range(32):
        print(f"r{i}: {computer.registers[i]:08X}")  # Print register values in hexadecimal
    print("==End of Registers for verification==")

if __name__ == '__main__':
    print('Hello Run.py')

    # Demo test 1, just test translate assembly command to binary
    '''
    demo_test_assembler()
    '''

    # Demo test 2, run a set of assembly commands
    demo_test_run_assembly_command()