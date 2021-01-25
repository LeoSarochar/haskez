#!/usr/bin/ruby
# Jankun Norminette
# Based on normez, edited by LÃ©o Sarochar 2020.

require 'optparse'
require 'tmpdir'

$major = 0
$minor = 0
$info = 0

class String
  def each_char
    split('').each { |i| yield i }
  end

  def add_style(color_code)
    if $options.include? :colorless
      "#{self}"
    else
      "\e[#{color_code}m#{self}\e[0m"
    end
  end

  def black
    add_style(31)
  end

  def red
    add_style(31)
  end

  def green
    add_style(32)
  end

  def yellow
    add_style(33)
  end

  def blue
    add_style(34)
  end

  def magenta
    add_style(35)
  end

  def cyan
    add_style(36)
  end

  def grey
    add_style(37)
  end

  def bold
    add_style(1)
  end

  def italic
    add_style(3)
  end

  def underline
    add_style(4)
  end
end

module FileType
  UNKNOWN = 0
  DIRECTORY = 1
  MAKEFILE = 2
  HEADER = 3
  SOURCE = 4
end

class FileManager
  attr_accessor :path
  attr_accessor :type

  def initialize(path, type)
    @path = path
    @type = type
    @type = get_file_type if @type == FileType::UNKNOWN
  end

  def get_file_type
    @type = if @path =~ /Makefile$/
              FileType::MAKEFILE
            elsif @path =~ /[.]hs$/
              FileType::SOURCE
            else
              FileType::UNKNOWN
            end
  end

  def get_content
    file = File.open(@path)
    content = file.read
    file.close
    content
  end
end

class FilesRetriever
  @@ignore = []

  def initialize
    @files = Dir['**/*'].select { |f| File.file? f }
    if File.file?('.gitignore')
      line_num = 0
      gitignore = FileManager.new('.gitignore', FileType::UNKNOWN).get_content
      gitignore.gsub!(/\r\n?/, "\n")
      gitignore.each_line do |line|
        if !line.start_with?('#') && line !~ /^\s*$/
          @@ignore.push(line.chomp)
        end
      end
    end

    @@ignore.push("tests/*") #ignoring tests files
    @@ignore.push("students")
    @nb_files = @files.size
    @idx_files = 0

    @dirs = Dir['**/*'].select { |d| File.directory? d }
    @nb_dirs = @dirs.size
    @idx_dirs = 0
  end

  def is_ignored_file(file)
    @@ignore.each do |ignored_file|
      if (ignored_file.include? "*")
        if file.include?(ignored_file) || file.include?(ignored_file.tr('*', ''))
          return true
        end
      elsif file == ignored_file
          return true
      end
    end
    false
  end

  def get_next_file
    if @idx_files < @nb_files
      file = FileManager.new(@files[@idx_files], FileType::UNKNOWN)
      @idx_files += 1
      file = get_next_file if !@@ignore.nil? && is_ignored_file(file.path)
      return file
    elsif @idx_dirs < @nb_dirs
      file = FileManager.new(@dirs[@idx_dirs], FileType::DIRECTORY)
      @idx_dirs += 1
      file = get_next_file if !@@ignore.nil? && is_ignored_file(file.path)
      return file
    end
    nil
  end
end

class CodingStyleChecker
  def initialize(file_manager)
    @file_path = file_manager.path
    @type = file_manager.type
    @file = nil
    if (@type != FileType::UNKNOWN) && (@type != FileType::DIRECTORY)
      @file = file_manager.get_content
    end
    check_file
  end

  def check_file
    if @type == FileType::UNKNOWN
      unless $options.include? :ignorefiles
        msg_brackets = '[' + @file_path + ']'
        msg_error = ' O1 - Your delivery folder should contain only files required for compilation.'
        $major += 1
        puts(msg_brackets.bold.red + msg_error.bold)
      end
      return
    end
    if @type == FileType::DIRECTORY
      check_dirname
      return
    end
    check_trailing_spaces_tabs
    if @type != FileType::MAKEFILE
      check_filename
      check_too_many_columns
      check_too_broad_filename

      if @type == FileType::SOURCE
        check_function_lines
        check_top_level_binding
        check_mutable_variables
        check_function_name
        check_identifier_lowercase
        check_too_many_else_if
        check_guard_pattern_matching
        check_useless_do
      end
    elsif @type == FileType::MAKEFILE
      check_header_makefile
    end
  end

  def check_dirname
    filename = File.basename(@file_path)
    if filename !~ /^[a-z0-9]+([a-z0-9_]+[a-z0-9]+)*$/
      msg_brackets = '[' + @file_path + ']'
      msg_error = ' O4 - Directory names should respect the snake_case naming convention'
      $major += 1
      puts(msg_brackets.bold.red + msg_error.bold)
    end
  end

  def check_filename
    filename = File.basename(@file_path)
    if filename !~ /^[A-Z]+[a-z0-9]*/
      msg_brackets = '[' + @file_path + ']'
      msg_error = ' O4 - Filenames should respect the camel_case naming convention'
      $major += 1
      puts(msg_brackets.bold.red + msg_error.bold)
    end
  end

  def check_too_many_columns
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      length = 0
      line.each_char do |char|
        length += if char == "\t"
                    8
                  else
                    1
                  end
      end
      if length - 1 > 80
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = ' F3 - Too long line (' + (length - 1).to_s + ' > 80)'
        $major += 1
        puts(msg_brackets.bold.red + msg_error.bold)
      end
      line_nb += 1
    end
  end

  def check_too_broad_filename
    if @file_path =~ /(.*\/|^)(string.c|str.c|my_string.c|my_str.c|algorithm.c|my_algorithm.c|algo.c|my_algo.c|program.c|my_program.c|prog.c|my_prog.c|program.c)$/
      msg_brackets = '[' + @file_path + ']'
      msg_error = ' O4 - Too broad filename. You should rename this file'
      $major += 1
      puts(msg_brackets.bold.red + msg_error.bold)
    end
  end

  def check_header
    line_nb = 1
    header_first_line = 1
    @file.each_line do |line|
      if line_nb == 1 && line !~ /\/\*/
        header_first_line = 0
      end
      line_nb += 1
    end
    if header_first_line == 0 || @file !~ /\/\*\n\*\* EPITECH PROJECT, [0-9]{4}\n\*\* .*\n\*\* File description:\n(\*\* .*\n)+\*\/\n.*/
      msg_brackets = '[' + @file_path + ']'
      msg_error = ' G1 - You must start your source code with a correctly formatted Epitech standard header'
      $major += 1
      puts(msg_brackets.bold.red + msg_error.bold)
    end
  end

  def check_function_lines
    sec_count = 0
    count = -1
    line_nb = 1
    function_start = -1
    many_lines = []
    @file.each_line do |line|
        if function_start != -1
            if line =~ /^\s*--/ #Skip commented lines
                line_nb += 1;
                next;
            end
            if line =~ /(^[a-zA-Z0-9]*).\s*::\s*/
                many_lines.each do |line_index|
                    msg_brackets = '[' + @file_path + ':' + line_index.to_s + ']'
                    msg_error = ' F4 - Too long function'
                    $major += 1
                    puts(msg_brackets.bold.red + msg_error.bold)
                end
                function_start = -1
                many_lines = []
                sec_count = 0
            else
                count += 1
                sec_count += 1
                if (count > 10 && sec_count > 4)
                    many_lines.push(line_nb);
                    sec_count = 0
                end
            end
        else
            if line =~ /(^[a-zA-Z0-9]*).\s*::\s*/
                function_start = line_nb
                count = 0
            end
        end
        line_nb += 1
    end
    many_lines.each do |line_index|
        msg_brackets = '[' + @file_path + ':' + line_index.to_s + ']'
        msg_error = ' F4 - Too long function'
        $major += 1
        puts(msg_brackets.bold.red + msg_error.bold)
    end
    function_start = -1
    many_lines = []
    sec_count = 0
  end

  def check_forbidden_keyword_func
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      line.scan(/(^|[^0-9a-zA-Z_])(printf|dprintf|fprintf|vprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|asprintf|scranf|memcpy|memset|memmove|strcat|strchar|strcpy|atoi|strlen|strncat|strncpy|strcasestr|strncasestr|strcmp|strncmp|strtok|strnlen|strdup|realloc)[^0-9a-zA-Z]/) do
        unless $options.include? :ignorefunctions
          msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
          msg_error = " Are you sure that this function is allowed: '".bold
          msg_error += Regexp.last_match(2).bold.red
          msg_error += "'?".bold
          puts(msg_brackets.bold.red + msg_error)
        end
      end
      line.scan(/(^|[^0-9a-zA-Z_])(goto)[^0-9a-zA-Z]/) do
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = " C3 - Your code should not contain the goto keyword."
        $minor += 1
        puts(msg_brackets.bold.red + msg_error)
      end
      line_nb += 1
    end
  end

  def check_top_level_binding
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      line[0] = '' while [' ', "\t"].include?(line[0])
      if line =~ /^main*/ && line !~ /^main\s*::\s*IO\s*\(\)/
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = " T1 - All top level bindings must have an accompanying type signature.".bold
        $major += 1
        puts(msg_brackets.bold.red + msg_error)
      end
      line_nb += 1
    end
  end

  def check_mutable_variables
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      line.scan(/(^|[^0-9a-zA-Z_])(IORef|STRef|TVar)/) do
        unless $options.include? :ignorefunctions
          msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
          msg_error = " M1 - Mutable variables are strictly forbidden : ".bold
          msg_error += Regexp.last_match(2).bold.red
          $major += 1
          puts(msg_brackets.bold.red + msg_error)
        end
      end
      line_nb += 1
    end
  end

  def check_function_name
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      line.scan(/(^[a-zA-Z0-9]*).\s*::\s*/) do
        if Regexp.last_match(1) !~ /^[a-z0-9]+([a-z0-9_]+[a-z0-9]+)*/
            msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
            msg_error = " F2 - All function names should be in English, according to the lowerCamelCase convention."
            $minor += 1
            puts(msg_brackets.bold.green + msg_error)
        end
      end
      line_nb += 1
    end
  end

  def check_too_many_else_if
    count = 0
    count_if = 0
    line_nb = 1
    function_start = -1
    @file.each_line do |line|
        if function_start != -1
            if line =~ /^\s*--/ #Skip commented lines
                line_nb += 1;
                next;
            end
            if line =~ /(^[a-zA-Z0-9]*).\s*::\s*/
               if count >= 3 || count_if >= 2
                    msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
                    msg_error = " C1 - Nested If statements are stricly forbidden.".bold
                    $major += 1
                    puts(msg_brackets.bold.red + msg_error)
               end
               function_start = -1
            else
                if line =~ /if/
                    count_if += 1
                end
                if line =~ /(?!\|)\s*\|\s*(?!\|)/ 
                    count += 1
                end
            end
        else
            if line =~ /(^[a-zA-Z0-9]*).\s*::\s*/
                function_start = line_nb
                count = 0
                count_if = 0
            end
        end
        line_nb += 1
    end
    if count >= 3 || count_if >= 2
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = " C1 - Nested If statements are stricly forbidden.".bold
        $major += 1
        puts(msg_brackets.bold.red + msg_error)
    end
  end

  def check_guard_pattern_matching
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      if line =~ /==\s*\[\s*\]/
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = " C2 - Guards which can be expressed as pattern matchings must be expressed as such.".bold
        $major += 1
        puts(msg_brackets.bold.red + msg_error)
      end
      line_nb += 1
    end
  end

  def check_trailing_spaces_tabs
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      if line =~ / $/
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = ' L3 - Trailing space(s) at the end of the line'
        $minor += 1
        puts(msg_brackets.bold.green + msg_error.bold)
      elsif line =~ /\t$/
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = ' L3 - Trailing tabulation(s) at the end of the line'
        $minor += 1
        puts(msg_brackets.bold.green + msg_error.bold)
      end
      line_nb += 1
    end
  end

  def check_useless_do
    arrow_found = 0
    line_nb = 1
    function_start = -1
    @file.each_line do |line|
        if function_start != -1
            if line =~ /^\s*--/ #Skip commented lines
                line_nb += 1;
                next;
            end
            if line =~ /(^[a-zA-Z0-9]*).\s*::\s*/
               if arrow_found == 0
                    msg_brackets = '[' + @file_path + ':' + function_start.to_s + ']'
                    msg_error = " D1 - The Do notation is forbidden unless it contains a generator (a statement with a left arrow).".bold
                    $major += 1
                    puts(msg_brackets.bold.red + msg_error)
               end
               function_start = -1
            else
                if line =~ /<-/
                    arrow_found = 1
                end
            end
        else
            if line =~ /\s*=\s*do/
                function_start = line_nb
            end
        end
        line_nb += 1
    end
    if function_start != -1 && arrow_found == 0
        msg_brackets = '[' + @file_path + ':' + function_start.to_s + ']'
        msg_error = " D1 - The Do notation is forbidden unless it contains a generator (a statement with a left arrow).".bold
        $major += 1
        puts(msg_brackets.bold.red + msg_error)
    end
  end

  def check_indentation
    line_nb = 1
    if @type == FileType::MAKEFILE
      valid_indent = '\t'
      bad_indent_regexp = /^ +.*$/
      bad_indent_name = 'space'
    else
      valid_indent = ' '
      bad_indent_regexp = /^\t+.*$/
      bad_indent_name = 'tabulation'
    end
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      indent = 0
      while line[indent] == valid_indent
        indent += 1
      end
      if line =~ bad_indent_regexp
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = " L2 - Wrong indentation: #{bad_indent_name}s are not allowed."
        $minor += 1
        puts(msg_brackets.bold.green + msg_error.bold)
      elsif indent % 4 != 0
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = ' L2 - Wrong indentation'
        $minor += 1
        puts(msg_brackets.bold.green + msg_error.bold)
      end
      line_nb += 1
    end
  end

  def check_empty_parenthesis
    line_nb = 1
    missing_bracket = false
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      if line =~ /^.*?(unsigned|signed)?\s*(void|int|char|short|long|float|double)\s+(\w+)\s*\(\)\s*[^;]/
          msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
          msg_error = " F5 - This function takes no parameter, it should take 'void' as argument."
          $major += 1
          puts(msg_brackets.bold.red + msg_error.bold)
      end
      line_nb += 1
    end
  end

  def check_header_makefile
    if @file !~ /##\n## EPITECH PROJECT, [0-9]{4}\n## .*\n## File description:\n## .*\n##\n.*/
      msg_brackets = '[' + @file_path + ']'
      msg_error = ' G1 - You must start your source code with a correctly formatted Epitech standard header.'
      $major += 1
      puts(msg_brackets.bold.red + msg_error.bold)
    end
  end


  def put_error_sign(sign, line_nb)
    msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
    msg_error = " L3 - Misplaced space(s) around '" + sign + "' sign."
    $minor += 1
    puts(msg_brackets.bold.green + msg_error.bold)
  end

  def check_operators_spaces
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      # A space on both ends
      line.scan(/([^\t&|=^><+\-*%\/! ]=[^=]|[^&|=^><+\-*%\/!]=[^= \n])/) do
        put_error_sign('=', line_nb)
      end
      line.scan(/([^\t ]==|==[^ \n])/) do
        put_error_sign('==', line_nb)
      end
      line.scan(/([^\t ]!=|!=[^ \n])/) do
        put_error_sign('!=', line_nb)
      end
      line.scan(/([^\t <]<=|[^<]<=[^ \n])/) do
        put_error_sign('<=', line_nb)
      end
      line.scan(/([^\t >]>=|[^>]>=[^ \n])/) do
        put_error_sign('>=', line_nb)
      end
      line.scan(/([^\t ]&&|&&[^ \n])/) do
        put_error_sign('&&', line_nb)
      end
      line.scan(/([^\t ]\|\||\|\|[^ \n])/) do
        put_error_sign('||', line_nb)
      end
      line.scan(/([^\t ]\+=|\+=[^ \n])/) do
        put_error_sign('+=', line_nb)
      end
      line.scan(/([^\t ]-=|-=[^ \n])/) do
        put_error_sign('-=', line_nb)
      end
      line.scan(/([^\t ]\*=|\*=[^ \n])/) do
        put_error_sign('*=', line_nb)
      end
      line.scan(/([^\t ]\/=|\/=[^ \n])/) do
        put_error_sign('/=', line_nb)
      end
      line.scan(/([^\t ]%=|%=[^ \n])/) do
        put_error_sign('%=', line_nb)
      end
      line.scan(/([^\t ]&=|&=[^ \n])/) do
        put_error_sign('&=', line_nb)
      end
      line.scan(/([^\t ]\^=|\^=[^ \n])/) do
        put_error_sign('^=', line_nb)
      end
      line.scan(/([^\t ]\|=|\|=[^ \n])/) do
        put_error_sign('|=', line_nb)
      end
      line.scan(/([^\t |]\|[^|]|[^|]\|[^ =|\n])/) do
        # Minifix for Matchstick
        line.scan(/([^'"]\|[^'"])/) do
          put_error_sign('|', line_nb)
        end
      end
      line.scan(/([^\t ]\^|\^[^ =\n])/) do
        line.scan(/([^'"]\^|\^[^'"])/) do
          put_error_sign('^', line_nb)
        end
      end
      line.scan(/([^\t ]>>[^=]|>>[^ =\n])/) do
        line.scan(/([^'"]>>[^=]|>>[^'"])/) do
          put_error_sign('>>', line_nb)
        end
      end
      line.scan(/([^\t ]<<[^=]|<<[^ =\n])/) do
        line.scan(/([^'"]<<[^=]|<<[^'"])/) do
          put_error_sign('<<', line_nb)
        end
      end
      line.scan(/([^\t ]>>=|>>=[^ \n])/) do
        put_error_sign('>>=', line_nb)
      end
      line.scan(/([^\t ]<<=|<<=[^ \n])/) do
        put_error_sign('<<=', line_nb)
      end
      # No space after
      line.scan(/([^!]! )/) do
        put_error_sign('!', line_nb)
      end
      line.scan(/([^a-zA-Z0-9]sizeof )/) do
        put_error_sign('sizeof', line_nb)
      end
      line.scan(/([^a-zA-Z)\]]\+\+[^(\[*a-zA-Z])/) do
        put_error_sign('++', line_nb)
      end
      line.scan(/([^a-zA-Z)\]]--[^\[(*a-zA-Z])/) do
        line.scan(/([^'"]--[^'"])/) do
          put_error_sign('--', line_nb)
        end
      end
      line.scan(/ ;$/) do
        put_error_sign(';', line_nb)
      end
      line_nb += 1
    end
  end

  def check_condition_assignment
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      line.scan(/(if.*[^&|=^><+\-*%\/!]=[^=].*==.*)|(if.*==.*[^&|=^><+\-*%\/!]=[^=].*)/) do
        msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
        msg_error = ' L1 - Condition and assignment on the same line'
        $minor += 1
        puts(msg_brackets.bold.green + msg_error.bold)
      end
      line_nb += 1
    end
  end

  def check_identifier_lowercase
    line_nb = 1
    @file.each_line do |line|
      if line =~ /^\s*--/ #Skip commented lines
        line_nb += 1;
        next;
      end
      if line =~ (/let\s([a-zA-Z0-9]*)\s*/)
        if line !~ /let\s[a-z0-9]+\s*/
            msg_brackets = '[' + @file_path + ':' + line_nb.to_s + ']'
            msg_error = " V1 - All identifier names should be in English, according to the lowerCamelCase convention."
            $minor += 1
            puts(msg_brackets.bold.green + msg_error.bold)
        end
      end
      line_nb += 1
    end
  end
end


$options = {}
opt_parser = OptionParser.new do |opts|
  opts.banner = 'Usage: `ruby ' + $PROGRAM_NAME + ' [-ufmi]`'
  opts.on('-u', '--no-update', "Don't check for updates") do |o|
    $options[:noupdate] = o
  end
  opts.on('-f', '--ignore-files', 'Ignore forbidden files') do |o|
    $options[:ignorefiles] = o
  end
  opts.on('-m', '--ignore-functions', 'Ignore forbidden functions') do |o|
    $options[:ignorefunctions] = o
  end
  opts.on('-i', '--ignore-all', 'Ignore forbidden files & forbidden functions (same as `-fm`)') do |o|
    $options[:ignorefiles] = o
    $options[:ignorefunctions] = o
  end
  opts.on('-c', '--colorless', 'Disable output styling') do |o|
    $options[:colorless] = o
  end
end

begin
  opt_parser.parse!
rescue OptionParser::InvalidOption => e
  puts('Error: ' + e.to_s)
  puts(opt_parser.banner)
  Kernel.exit(false)
end

files_retriever = FilesRetriever.new
while (next_file = files_retriever.get_next_file)
  CodingStyleChecker.new(next_file)
end
puts("")
puts("Major : %s" % $major)
puts("Minor : %s" % $minor)
puts("Info : %s" % $info)