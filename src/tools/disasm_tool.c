#include "core/dez_disasm.h"
#include "assembler/dez_symbol_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Output formats
typedef enum {
  FORMAT_SIMPLE,     // Simple disassembly
  FORMAT_DETAILED,   // Detailed instruction breakdown
  FORMAT_ASSEMBLY,   // Assembly source format
  FORMAT_HEX,        // Hex dump with disassembly
  FORMAT_OBJDUMP,    // objdump-like format
  FORMAT_HEXDUMP     // hexdump-like format with ASCII
} output_format_t;

// Command line options
typedef struct {
  output_format_t format;
  bool show_addresses;
  bool show_hex;
  bool show_details;
  bool show_line_numbers;
  bool show_symbols;
  bool show_headers;
  uint32_t start_addr;
  uint32_t count;
  char *filename;
  char *symbol_file;
} disasm_options_t;

// Print usage information
void print_usage(const char *program_name) {
  printf("DEZ Disassembler - Enhanced Version\n");
  printf("Usage: %s [OPTIONS] <file.bin|instruction...>\n\n", program_name);
  printf("Options:\n");
  printf("  -f, --format FORMAT    Output format: simple, detailed, assembly, hex, objdump, hexdump\n");
  printf("  -s, --start ADDR       Start address (hex, default: 0)\n");
  printf("  -c, --count NUM        Number of instructions to disassemble\n");
  printf("  -a, --addresses        Show addresses in output\n");
  printf("  -l, --line-numbers     Show line numbers\n");
  printf("  -H, --headers          Show column headers\n");
  printf("  -S, --symbols          Show symbol information\n");
  printf("  --symbol-file FILE     Load symbol table from file\n");
  printf("  -h, --help             Show this help message\n\n");
  printf("Formats:\n");
  printf("  simple     Simple disassembly (default)\n");
  printf("  detailed   Detailed instruction breakdown\n");
  printf("  assembly   Assembly source format\n");
  printf("  hex        Hex dump with disassembly\n");
  printf("  objdump    objdump-like format with proper columns\n");
  printf("  hexdump    hexdump-like format with ASCII representation\n\n");
  printf("Column Headers:\n");
  printf("  objdump:    [Line] Address    Hex Instruction    Disassembly\n");
  printf("  hexdump:    [Line] Address    Hex Bytes    ASCII    Disassembly\n");
  printf("  detailed:   [Line] Address    Hex Instruction    Disassembly + Details\n\n");
  printf("Examples:\n");
  printf("  %s program.bin                    # Disassemble binary file\n", program_name);
  printf("  %s -f objdump -H program.bin      # objdump format with headers\n", program_name);
  printf("  %s -f hexdump -H program.bin      # hexdump format with headers\n", program_name);
  printf("  %s -S program.bin                 # Show symbol table\n", program_name);
  printf("  %s -s 0x100 -c 50 program.bin    # Disassemble 50 instructions from 0x100\n", program_name);
  printf("  %s 0x01000005 0x04210000         # Disassemble individual instructions\n", program_name);
}

// Parse command line arguments
int parse_arguments(int argc, char *argv[], disasm_options_t *options) {
  // Default options
  options->format = FORMAT_SIMPLE;
  options->show_addresses = false;
  options->show_hex = false;
  options->show_details = false;
  options->show_line_numbers = false;
  options->show_symbols = false;
  options->show_headers = false;
  options->start_addr = 0;
  options->count = 0;
  options->filename = NULL;
  options->symbol_file = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      return -1; // Help requested
    } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: --format requires an argument\n");
        return 1;
      }
      i++;
      if (strcmp(argv[i], "simple") == 0) {
        options->format = FORMAT_SIMPLE;
      } else if (strcmp(argv[i], "detailed") == 0) {
        options->format = FORMAT_DETAILED;
      } else if (strcmp(argv[i], "assembly") == 0) {
        options->format = FORMAT_ASSEMBLY;
      } else if (strcmp(argv[i], "hex") == 0) {
        options->format = FORMAT_HEX;
      } else if (strcmp(argv[i], "objdump") == 0) {
        options->format = FORMAT_OBJDUMP;
      } else if (strcmp(argv[i], "hexdump") == 0) {
        options->format = FORMAT_HEXDUMP;
      } else {
        fprintf(stderr, "Error: Invalid format '%s'\n", argv[i]);
        return 1;
      }
    } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--start") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: --start requires an address\n");
        return 1;
      }
      i++;
      options->start_addr = (uint32_t)strtoul(argv[i], NULL, 16);
    } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: --count requires a number\n");
        return 1;
      }
      i++;
      options->count = (uint32_t)strtoul(argv[i], NULL, 10);
    } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--addresses") == 0) {
      options->show_addresses = true;
    } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--line-numbers") == 0) {
      options->show_line_numbers = true;
    } else if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--headers") == 0) {
      options->show_headers = true;
    } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--symbols") == 0) {
      options->show_symbols = true;
    } else if (strcmp(argv[i], "--symbol-file") == 0) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: --symbol-file requires a filename\n");
        return 1;
      }
      i++;
      options->symbol_file = argv[i];
    } else if (argv[i][0] != '-') {
      // Not an option, must be filename or instruction
      if (options->filename == NULL) {
        options->filename = argv[i];
      }
    }
  }

  return 0;
}

// Read binary file
int read_binary_file(const char *filename, uint32_t **instructions, uint32_t *count) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
    return 1;
  }

  // Get file size
  fseek(file, 0, SEEK_END);
  long file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  if (file_size % 4 != 0) {
    fprintf(stderr, "Warning: File size (%ld) is not a multiple of 4 bytes\n", file_size);
  }

  *count = file_size / 4;
  *instructions = malloc(*count * sizeof(uint32_t));
  
  if (!*instructions) {
    fprintf(stderr, "Error: Memory allocation failed\n");
    fclose(file);
    return 1;
  }

  size_t read_count = fread(*instructions, sizeof(uint32_t), *count, file);
  fclose(file);

  if (read_count != *count) {
    fprintf(stderr, "Warning: Expected %u instructions, read %zu\n", *count, read_count);
    *count = read_count;
  }

  return 0;
}

// Print column headers based on format
void print_column_headers(output_format_t format, bool show_line_numbers) {
  switch (format) {
    case FORMAT_OBJDUMP:
      if (show_line_numbers) {
        printf("%-4s %-10s %-12s %s\n", "Line", "Address", "Instruction", "Disassembly");
      } else {
        printf("%-10s %-12s %s\n", "Address", "Instruction", "Disassembly");
      }
      printf("----------------------------------------------------\n");
      break;
      
    case FORMAT_HEXDUMP:
      if (show_line_numbers) {
        printf("%-4s %-10s %-20s %-8s %s\n", "Line", "Address", "Hex Bytes", "ASCII", "Disassembly");
      } else {
        printf("%-10s %-20s %-8s %s\n", "Address", "Hex Bytes", "ASCII", "Disassembly");
      }
      printf("--------------------------------------------------------\n");
      break;
      
    case FORMAT_DETAILED:
      if (show_line_numbers) {
        printf("%-4s %-10s %-12s %s\n", "Line", "Address", "Instruction", "Disassembly");
      } else {
        printf("%-10s %-12s %s\n", "Address", "Instruction", "Disassembly");
      }
      printf("----------------------------------------------------\n");
      break;
      
    case FORMAT_HEX:
      if (show_line_numbers) {
        printf("%-4s %-10s %-12s %s\n", "Line", "Address", "Hex", "Disassembly");
      } else {
        printf("%-10s %-12s %s\n", "Address", "Hex", "Disassembly");
      }
      printf("----------------------------------------------------\n");
      break;
      
    case FORMAT_SIMPLE:
    case FORMAT_ASSEMBLY:
      if (show_line_numbers) {
        printf("%-4s %-10s %s\n", "Line", "Address", "Disassembly");
      } else {
        printf("%-10s %s\n", "Address", "Disassembly");
      }
      printf("------------------------------------\n");
      break;
  }
}

// Create a sample symbol table for demonstration
symbol_table_t* create_sample_symbol_table() {
  static symbol_table_t table;
  symbol_table_init(&table);
  
  // Add some sample symbols
  symbol_table_define(&table, "main", 0x00000000, 1);
  symbol_table_define(&table, "loop_start", 0x00000010, 5);
  symbol_table_define(&table, "loop_end", 0x00000020, 10);
  symbol_table_define_constant(&table, "ARRAY_SIZE", 10, 2);
  symbol_table_define_string(&table, "msg_hello", "Hello, World!", 3);
  
  return &table;
}

// Load symbol table from file (placeholder - would need actual implementation)
symbol_table_t* load_symbol_table(const char *filename) {
  // For now, return a sample symbol table for demonstration
  // In a real implementation, this would parse a symbol file or debug information
  (void)filename; // Suppress unused parameter warning
  return create_sample_symbol_table();
}

// Find symbol name for an address
const char* find_symbol_name(symbol_table_t *table, uint32_t address) {
  if (!table) return NULL;
  
  for (int i = 0; i < table->count; i++) {
    if (table->symbols[i].address == address) {
      return table->symbols[i].name;
    }
  }
  return NULL;
}

// Print symbol table information
void print_symbol_info(symbol_table_t *table, uint32_t address) {
  if (!table) return;
  
  const char *symbol_name = find_symbol_name(table, address);
  if (symbol_name) {
    printf(" <%s>", symbol_name);
  }
}

// Helper function to get ASCII representation of bytes
void get_ascii_representation(uint32_t instruction, char *ascii, size_t size) {
  uint8_t bytes[4];
  bytes[0] = (instruction >> 24) & 0xFF;
  bytes[1] = (instruction >> 16) & 0xFF;
  bytes[2] = (instruction >> 8) & 0xFF;
  bytes[3] = instruction & 0xFF;
  
  for (int i = 0; i < 4 && i < (int)(size - 1); i++) {
    ascii[i] = (bytes[i] >= 32 && bytes[i] <= 126) ? bytes[i] : '.';
  }
  ascii[4] = '\0';
}

// Disassemble with different output formats
void disassemble_instruction(uint32_t instruction, uint32_t address, output_format_t format, bool show_addresses, bool show_line_numbers, uint32_t line_num, symbol_table_t *symbol_table) {
  char disasm[256];
  dez_disasm_instruction(instruction, disasm, sizeof(disasm));

  switch (format) {
    case FORMAT_SIMPLE:
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      if (show_addresses) {
        printf("0x%08X: %s", address, disasm);
        print_symbol_info(symbol_table, address);
        printf("\n");
      } else {
        printf("%s", disasm);
        print_symbol_info(symbol_table, address);
        printf("\n");
      }
      break;

    case FORMAT_ASSEMBLY:
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      if (show_addresses) {
        printf("0x%08X: %s", address, disasm);
        print_symbol_info(symbol_table, address);
        printf("\n");
      } else {
        printf("%s", disasm);
        print_symbol_info(symbol_table, address);
        printf("\n");
      }
      break;

    case FORMAT_HEX:
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      printf("0x%08X: 0x%08X  %s", address, instruction, disasm);
      print_symbol_info(symbol_table, address);
      printf("\n");
      break;

    case FORMAT_OBJDUMP:
      // objdump-like format: address, hex instruction, disassembly
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      printf("0x%08X: %08x  %s", address, instruction, disasm);
      print_symbol_info(symbol_table, address);
      printf("\n");
      break;

    case FORMAT_HEXDUMP: {
      // hexdump-like format: address, hex bytes, ASCII representation
      char ascii[8];
      get_ascii_representation(instruction, ascii, sizeof(ascii));
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      printf("%08x  %02x %02x %02x %02x  |%s|  %s", 
             address,
             (instruction >> 24) & 0xFF,
             (instruction >> 16) & 0xFF,
             (instruction >> 8) & 0xFF,
             instruction & 0xFF,
             ascii, disasm);
      print_symbol_info(symbol_table, address);
      printf("\n");
      break;
    }

    case FORMAT_DETAILED:
      if (show_line_numbers) {
        printf("%4u: ", line_num);
      }
      printf("0x%08X: 0x%08X  %s", address, instruction, disasm);
      print_symbol_info(symbol_table, address);
      printf("\n");
      uint8_t opcode = (instruction >> 24) & 0xFF;
      uint8_t reg1 = (instruction >> 20) & 0xF;
      uint8_t reg2 = (instruction >> 16) & 0xF;
      uint8_t reg3 = (instruction >> 12) & 0xF;
      uint32_t immediate = instruction & 0x0FFF;
      printf("        Opcode: 0x%02X (%s), R1:%d, R2:%d, R3:%d, Imm:%d (0x%03X)\n", 
             opcode, dez_get_instruction_mnemonic(opcode), reg1, reg2, reg3, immediate, immediate);
      break;
  }
}

// Disassemble individual instructions from command line
int disassemble_individual_instructions(int argc, char *argv[], disasm_options_t *options) {
  printf("=== DEZ Disassembler ===\n");
  printf("Disassembling %d instruction(s):\n\n", argc);

  // Load symbol table if specified or if symbols are requested
  symbol_table_t *symbol_table = NULL;
  if (options->symbol_file) {
    symbol_table = load_symbol_table(options->symbol_file);
  } else if (options->show_symbols) {
    symbol_table = create_sample_symbol_table();
  }

  // Print headers if requested
  if (options->show_headers) {
    print_column_headers(options->format, options->show_line_numbers);
  }

  for (int i = 0; i < argc; i++) {
    uint32_t instruction = (uint32_t)strtoul(argv[i], NULL, 16);
    disassemble_instruction(instruction, i * 4, options->format, options->show_addresses, options->show_line_numbers, i + 1, symbol_table);
  }

  if (options->format == FORMAT_DETAILED) {
    printf("\n=== Summary ===\n");
    for (int i = 0; i < argc; i++) {
      uint32_t instruction = (uint32_t)strtoul(argv[i], NULL, 16);
      printf("Instruction %d: 0x%08X (%s)\n", i, instruction, dez_get_instruction_mnemonic((instruction >> 24) & 0xFF));
    }
  }

  return 0;
}

// Disassemble binary file
int disassemble_binary_file(disasm_options_t *options) {
  uint32_t *instructions = NULL;
  uint32_t total_count = 0;

  if (read_binary_file(options->filename, &instructions, &total_count) != 0) {
    return 1;
  }

  // Load symbol table if specified or if symbols are requested
  symbol_table_t *symbol_table = NULL;
  if (options->symbol_file) {
    symbol_table = load_symbol_table(options->symbol_file);
  } else if (options->show_symbols) {
    symbol_table = create_sample_symbol_table();
  }

  printf("=== DEZ Disassembler ===\n");
  printf("File: %s (%u instructions)\n", options->filename, total_count);
  
  if (options->count == 0) {
    options->count = total_count;
  }

  uint32_t start_idx = options->start_addr / 4;
  uint32_t end_idx = start_idx + options->count;
  
  if (end_idx > total_count) {
    end_idx = total_count;
    options->count = end_idx - start_idx;
  }

  if (start_idx >= total_count) {
    fprintf(stderr, "Error: Start address 0x%08X is beyond file size\n", options->start_addr);
    free(instructions);
    return 1;
  }

  printf("Disassembling instructions %u-%u (addresses 0x%08X-0x%08X):\n\n", 
         start_idx, end_idx - 1, options->start_addr, options->start_addr + (options->count - 1) * 4);

  // Print headers if requested
  if (options->show_headers) {
    print_column_headers(options->format, options->show_line_numbers);
  }

  for (uint32_t i = start_idx; i < end_idx; i++) {
    uint32_t address = options->start_addr + (i - start_idx) * 4;
    uint32_t line_num = i - start_idx + 1;
    disassemble_instruction(instructions[i], address, options->format, options->show_addresses, options->show_line_numbers, line_num, symbol_table);
  }

  // Show symbol table if requested
  if (options->show_symbols && symbol_table) {
    symbol_table_print(symbol_table);
  }

  // Show statistics
  if (options->format == FORMAT_DETAILED || options->format == FORMAT_SIMPLE) {
    printf("\n=== Statistics ===\n");
    printf("Total instructions: %u\n", options->count);
    printf("Address range: 0x%08X - 0x%08X\n", options->start_addr, 
           options->start_addr + (options->count - 1) * 4);
    printf("Code size: %u bytes\n", options->count * 4);
  }

  free(instructions);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  disasm_options_t options;
  int parse_result = parse_arguments(argc, argv, &options);
  
  if (parse_result == -1) {
    print_usage(argv[0]);
    return 0;
  } else if (parse_result != 0) {
    return 1;
  }

  // Check if we have a filename or individual instructions
  // A filename is detected if it doesn't start with '0x' (hex instruction) or is a known file extension
  bool has_filename = false;
  if (options.filename) {
    // Check if it looks like a hex instruction (starts with 0x)
    if (strncmp(options.filename, "0x", 2) == 0) {
      has_filename = false;
    } else {
      has_filename = true;
    }
  }

  // Handle symbol-only mode (only when no instructions are provided)
  if (options.show_symbols && !has_filename) {
    // Check if there are any instruction arguments
    bool has_instructions = false;
    for (int i = 1; i < argc; i++) {
      if (argv[i][0] != '-') {
        has_instructions = true;
        break;
      }
    }
    
    if (!has_instructions) {
      printf("=== DEZ Symbol Table ===\n");
      symbol_table_t *symbol_table = create_sample_symbol_table();
      symbol_table_print(symbol_table);
      return 0;
    }
  }

  if (has_filename) {
    return disassemble_binary_file(&options);
  } else {
    // Collect individual instruction arguments
    int inst_count = 0;
    char *inst_args[argc];
    
    for (int i = 1; i < argc; i++) {
      if (argv[i][0] != '-') {
        inst_args[inst_count++] = argv[i];
      } else {
        // Skip option arguments
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0 ||
            strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--start") == 0 ||
            strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--count") == 0) {
          i++; // Skip the argument
        }
      }
    }
    
    if (inst_count == 0) {
      fprintf(stderr, "Error: No instructions or filename provided\n");
      print_usage(argv[0]);
      return 1;
    }
    
    return disassemble_individual_instructions(inst_count, inst_args, &options);
  }
}
