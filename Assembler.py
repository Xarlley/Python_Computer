class Assembler:
    def __init__(self):
        # Define the mapping for instruction opcodes (5 bits)
        self.opcode_map = {
            "LOAD": 0b00001,
            "STORE": 0b00010,
            "ADD": 0b00011,
            "JGE": 0b00100  # Add JGE opcode
        }

    def translate_assembly(self, instructions):
        """Translate a list of assembly instructions into 32-bit machine code."""
        binary_instructions = []

        for instruction in instructions:
            parts = instruction.replace(",", "").split()
            opcode = self.opcode_map[parts[0]]
            operands = [self._parse_operand(p) for p in parts[1:]]

            # Pad operands with zeros if necessary
            while len(operands) < 3:
                operands.append(0)

            # Construct the 32-bit instruction: opcode + 3 operands
            binary_instruction = (opcode << 27) | (operands[0] << 18) | (operands[1] << 9) | operands[2]
            binary_instructions.append(binary_instruction)

        return binary_instructions

    def _parse_operand(self, operand):
        """Parse an operand as either a register or memory address."""
        if operand.startswith('r'):
            # Register: First bit is 1, lower 5 bits are the register number (r0 to r31)
            reg_num = int(operand[1:])  # Extract register number
            if reg_num < 0 or reg_num > 31:
                raise ValueError(f"Invalid register: {operand}")
            return (1 << 8) | reg_num  # Set the first bit to 1 and use the last 5 bits for register number
        elif operand.startswith('#'):
            # Memory address: Handle decimal or hexadecimal address
            if operand.startswith('#0x') or operand.startswith('#0X'):
                # Hexadecimal address
                address = int(operand[3:], 16)  # Convert hex string to integer
            else:
                # Decimal address
                address = int(operand[1:])  # Convert decimal string to integer
            
            if address < 0 or address > 255:
                raise ValueError(f"Invalid memory address: {operand}")
            return address  # No need to set the first bit, as it's already 0
        else:
            raise ValueError(f"Unknown operand format: {operand}")

    def print_binary_instructions(self, binary_instructions):
        """Helper method to print binary instructions in 32-bit format."""
        for instr in binary_instructions:
            print(f"{instr:032b}")  # Print as 32-bit binary
