#!/bin/bash
sed -i 's/\r//' chkf #removing tailing return keys in the file to prevent execution errors. It is optional but I had a few problems that is why I included it here
clear
echo   -e "\a"
declare -a server_log_files #Array to hold file logs
declare -a criteria
index=0
counter=1
pattern="serv_acc_log_.+csv$"

for file_name in * #find all the files in the current diretory
do
    if [[ $file_name =~ $pattern ]] #find only the server access file logs
    then     
        server_log_files["$index"]=$(basename $file_name) #populate the server_log_file array with the log files form the directory
        let index++ #increment the index each time until all the files are inserted into the array
    fi
done #terminate inner loop

function display_files(){   #this function allows a user to see and select a file from all the available csv files
local counter=1 #counter to use for numbering files
    echo -e "\nThere are $index server access log files\n"  #show the number of files present
    echo -e "\n"
     while :; do
        echo -e "\n"
        for ((i = 0 ; i < $index ; i++))
        do
            echo -e "\t$counter." "${server_log_files[$i]}"       #print out all the available files in a numbered format 
            let counter++
        done
        counter=1 #resetting counter to 1 each time a wrong option is entered. Otherwise the counter will continue incrementing
        echo -e "\n"
        read -p  "Select a log file to search e.g [1, 2, 3, 4 or 5]: " option #allow the user to select 1 file to perform searches on
        echo -e "\n"
        [[ $option =~ ^[0-9]+$ ]] || { echo "Enter a valid file option"; continue; } #check if the user entered the right option. If not continue prompting for the right option i.e they have entered a number
        if ((option >= 1 && option <= 5)); then #if they entered a number, check if the number is within the limit
            selection=${server_log_files[$option-1]} #if so, then get the file they selected
            echo -e "You want to search $selection\n" 
            grep "suspicious" $selection > tmpfile.csv #filter out the normal entries and remain with suspicious ones only
            break
        else
            echo -e "\nInvalid file option, try again\n" #if they enter a number and it is not within the limit, print this line
        fi
    done    
}


function create_output_file(){ #function to create a new file each time a successful search is performed 
    # local output_filename 
    read -p "Enter a file name to save your search: " output_filename     #allow user to enter a file name of their choosing
    if [[ -f "$output_filename.csv" ]] #check if the file name exists in the current directory
    then                    
        date_time=`date "+%Y%m%d-%H%M%S"` #if so, generate a timestamp
        output_filename=$output_filename$(date "+_%Y_%m%d_%H%M%S").csv  #append the timestamp to the file. This will make it unique since timestamps will never be the same, at least to a higher degree of certainty            
    else
        output_filename=$output_filename.csv   #if the file name does not exist yet, just use the name the user entered
    fi
    echo $output_filename #echo the file name in order to capture and use it in the caller funciton
}

#creating a menu
criteria[1]="PROTOCOL"
criteria[2]="SRC IP"
criteria[3]="SRC PORT"
criteria[4]="DEST IP"
criteria[5]="DEST PORT"
criteria[6]="PACKETS"
criteria[7]="BYTES"
criteria[8]="ADVANCED SEARCH"
criteria[9]="QUIT"
#end of creating menu

function validate_option(){   #this function validates user inputs. 
    if [[ $1 -ge $2 && $1 -le $3 && $1 =~ ^[0-9]+$ ]]; then
        return 1            
    else
        return 0            
    fi        
}

#**********************START OF SEARCH BASED ON PACKETS**********************#
function search_by_packet(){  #This function performs searches based on packets
    if [[ "$1" -eq 1 ]] #check the exact packet option the user intends to perform e.g packets greater than or packets equal to
    then        
        
        while :; do                        
            read -p "PACKETS > " num #read the input
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       #check if input entered is valid i.e it is a number or letter q
            if ((num != "q")) #if the input is valid but not letter q assign the input to a variable
            then
                num=$num
                break #break out of the loop
            elif ((num == "q")); then #if the user entered letter q, they want to exit the current menu
                show_available_search_options       #If so, go back to the main menu             
            else
                echo -e "\nInvalid option, try again\n" #In case none of the above is true, tell the user to try again entering the correct input
            fi
        done  
        local output_file=$(create_output_file)  #invoke the function that creates files and save the file created in a local variable

        awk -v var="$num" ' #run awk giving it the user input to perform a search based on the value
        BEGIN{
            FS=",";            
            #format the header to align properly with the data columns
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";   
        }
       {
        
            if($8 > var){     #filter out based on the column of interest  
            #print the formatted output     
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }
            
        }
        ' < tmpfile.csv > $output_file #feed awk the tmfile.csv, the file that has been filtered to remain with only the suspisous logs. At the same time, print the search result tot eh output file
        cat $output_file #print the output file to the terminal
        echo -e "\nYour search result has been save in $output_file\n"      
        #*******************The Code explation above is the same to the following options below*******************#

    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 2 ]]
    then
        
         while :; do                        
            read -p "PACKETS < " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
         local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 < var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;       
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
 #*******************The Code explation above is the same to the following options below*******************#

    #*******************The exaplanation for this code is the same to the code above*******************#    
    elif [[ "$1" -eq 3 ]]
    then
         while :; do                        
            read -p "PACKETS = " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 == var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                        
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
 #*******************The Code explation above is the same to the following options below*******************#

    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 4 ]]
    then
         while :; do                        
            read -p "PACKETS != " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 != var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    else
        echo "Invalid option"
    fi

}
#**********************END OF SEARCH BASED ON PACKECTS**********************#


#**********************START OF SEARCH BASED ON BYTES**********************#
function bytes(){  #This function performs searches based on bytes
    if [[ "$1" -eq 1 ]] #check the exact byte option the user intends to perform e.g bytes greater than or bytes equal to
    then
        
         while :; do                        
            read -p "BYTES > " num #read the input
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }  #check if input entered is valid i.e it is a number or letter q
            if ((num != "q")) #if the input is valid but not letter q assign the input to a variable
            then
                num=$num 
                break #break out of the loop
            elif ((num == "q")); then #if the user entered letter q, they want to exit the current menu
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n" #In case none of the above is true, tell the user to try again entering the correct input
            fi
        done 
        local output_file=$(create_output_file)  #invoke the function that creates files and save the file created in a local variable
        awk -v var="$num" ' #run awk giving it the user input to perform a search based on the value
        BEGIN{
            FS=",";
            # OFS="\t";
            #format the header to align properly with the data columns
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($9 > var){   #filter out based on the column of interest         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }
            
        }
        '  < tmpfile.csv > $output_file #feed awk the tmfile.csv, the file that has been filtered to remain with only the suspisous logs. At the same time, print the search result tot eh output file
        cat $output_file #print the output file to the terminal
        echo -e "\nYour search result has been save in $output_file\n"
         #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 2 ]]
    then
         while :; do                        
            read -p "BYTES < " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($9 < var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#    
    elif [[ "$1" -eq 3 ]]
    then
         while :; do                        
            read -p "BYTES = " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  

        }
        {
        
            if($9 == var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 4 ]]
    then
         while :; do                        
            read -p "BYTES != " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      

        }
        {
        
            if($9 != var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    else
        echo "Invalid option"
    fi
}
#**********************END OF SEARCH BASED ON BYTES**********************#


#**********************START OF SEARCH BASED ON SOURCE PORT**********************#
function search_by_source_port(){  #This function performs searches based on bytes
    if [[ "$1" -eq 1 ]] #check the exact byte option the user intends to perform e.g bytes greater than or bytes equal to
    then
        
         while :; do                        
            read -p "SOURCE PORT > " num #read the input
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 22 ] OR enter q to quit"; continue; }  #check if input entered is valid i.e it is a number or letter q
            if ((num != "q")) #if the input is valid but not letter q assign the input to a variable
            then
                num=$num 
                break #break out of the loop
            elif ((num == "q")); then #if the user entered letter q, they want to exit the current menu
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n" #In case none of the above is true, tell the user to try again entering the correct input
            fi
        done 
        local output_file=$(create_output_file)  #invoke the function that creates files and save the file created in a local variable
        awk -v var="$num" ' #run awk giving it the user input to perform a search based on the value
        BEGIN{
            FS=",";
            # OFS="\t";
            #format the header to align properly with the data columns
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($5 > var){   #filter out based on the column of interest         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }
            
        }
        '  < tmpfile.csv > $output_file #feed awk the tmfile.csv, the file that has been filtered to remain with only the suspisous logs. At the same time, print the search result tot eh output file
        cat $output_file #print the output file to the terminal
        echo -e "\nYour search result has been save in $output_file\n"
         #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 2 ]]
    then
         while :; do                        
            read -p "SOURCE PORT < " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($5 < var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                               
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#    
    elif [[ "$1" -eq 3 ]]
    then
         while :; do                        
            read -p "SOURCE PORT = " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";           
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($5 == var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 4 ]]
    then
         while :; do                        
            read -p "SOURCE PORT != " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      

        }
        {
        
            if($5 != var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
     
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    else
        echo "Invalid option"
    fi
}
#**********************END OF SEARCH BASED ON SOURCE PORT**********************#


#**********************START OF SEARCH BASED ON DESTINATION PORT**********************#
function search_by_dest_port(){  #This function performs searches based on bytes
    if [[ "$1" -eq 1 ]] #check the exact byte option the user intends to perform e.g bytes greater than or bytes equal to
    then
        
         while :; do                        
            read -p "DESTINATION PORT > " num #read the input
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 22 ] OR enter q to quit"; continue; }  #check if input entered is valid i.e it is a number or letter q
            if ((num != "q")) #if the input is valid but not letter q assign the input to a variable
            then
                num=$num 
                break #break out of the loop
            elif ((num == "q")); then #if the user entered letter q, they want to exit the current menu
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n" #In case none of the above is true, tell the user to try again entering the correct input
            fi
        done 
        local output_file=$(create_output_file)  #invoke the function that creates files and save the file created in a local variable
        awk -v var="$num" ' #run awk giving it the user input to perform a search based on the value
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($7 > var){   #filter out based on the column of interest         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }
            
        }
        '  < tmpfile.csv > $output_file #feed awk the tmfile.csv, the file that has been filtered to remain with only the suspisous logs. At the same time, print the search result tot eh output file
        cat $output_file #print the output file to the terminal
        echo -e "\nYour search result has been save in $output_file\n"
         #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 2 ]]
    then
         while :; do                        
            read -p "DESTINATION PORT < " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($7 < var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                               
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#    
    elif [[ "$1" -eq 3 ]]
    then
         while :; do                        
            read -p "DESTINATION PORT = " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";           
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($7 == var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;               
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"
  #*******************The Code explation above is the same to the following options below*******************#


    #*******************The exaplanation for this code is the same to the code above*******************#
    elif [[ "$1" -eq 4 ]]
    then
         while :; do                        
            read -p "DESTINATION PORT != " num
            [[ $num =~ ^[q0-9]+$ ]] || { echo "A valid input should be a number e.g [ 10 ] OR enter q to quit"; continue; }       
            if ((num != "q"))
            then
                num=$num
                break
            elif ((num == "q")); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done 
        local output_file=$(create_output_file)  
        awk -v var="$num" '
        BEGIN{
            FS=",";            
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      

        }
        {
        
            if($7 != var){            
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;      
            }
            
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    else
        echo "Invalid option"
    fi
}
#**********************END OF SEARCH BASED ON DESTINATION PORT**********************#



#**********************START OF SEARCH BASED ON SOURCE IP**********************#
function source_ip(){     
   if [[ $1 -eq 1 ]]
   then
    while :; do                        
        read -p "Enter search pattern e.g [EXT OR 1001]: " search_patt
        [[ $search_patt =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 3 to quit"; continue; }       
        if ((search_patt != 3))
        then
            search_pattern=$search_patt
            break
        elif ((search_patt == 3)); then
            show_available_search_options                    
        else
            echo -e "\nInvalid option, try again\n"
        fi
    done           
    local output_file=$(create_output_file) 
     var="$search_pattern" awk -F',' '$4 ~ ENVIRON["var"] {print $0}' tmpfile.csv | awk  '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      
            
        }
        {
            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
            
                                   
        } 
    ' > $output_file
    cat $output_file
    echo -e "\nYour search result has been save in $output_file\n"

    show_available_search_options
    elif [[ $1 -eq 2 ]]
    then
     while :; do                        
        read -p "Enter search pattern e.g [EXT OR 1001]: " search_patt
        [[ $search_patt =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 3 to quit"; continue; }       
        if ((search_patt != 3))
        then
            search_pattern=$search_patt
            break
        elif ((search_patt == 3)); then
            show_available_search_options                    
        else
            echo -e "\nInvalid option, try again\n"
        fi
    done      
    local output_file=$(create_output_file) 
        var="$search_pattern" awk -F',' '$4 !~ ENVIRON["var"] {print $0}' tmpfile.csv | awk  '
        BEGIN{
            FS=",";
            # OFS="\t";
            #  print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      
            
        }
        {
            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
            
                                   
        }
    ' > $output_file
    cat $output_file
    echo -e "\nYour search result has been save in $output_file\n"

    show_available_search_options
    else
        echo "You entered a wrong search option!"
    fi
}
#**********************END OF SEARCH BASED ON SOURCE IP**********************#


#**********************START OF SEARCH BASED ON DESTINATION IP**********************#
function dest_ip(){    
   if [[ $1 -eq 1 ]]
   then
    while :; do                        
        read -p "Enter search pattern e.g [EXT OR 1001]: " search_patt
        [[ $search_patt =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 3 to quit"; continue; }       
        if ((search_patt != 3))
        then
            search_pattern=$search_patt
            break
        elif ((search_patt == 3)); then
            show_available_search_options                    
        else
            echo -e "\nInvalid option, try again\n"
        fi
    done           
    local output_file=$(create_output_file) 
     var="$search_pattern" awk -F',' '$6 ~ ENVIRON["var"] {print $0}' tmpfile.csv | awk  '
        BEGIN{
            FS=",";
            # OFS="\t";
            #  print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      
            
        }
        {
            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
            
                                   
        }
    ' > $output_file
    cat $output_file
    echo -e "\nYour search result has been save in $output_file\n"

    show_available_search_options
    elif [[ $1 -eq 2 ]]
    then
     while :; do                        
        read -p "Enter search pattern e.g [EXT OR 1001]: " search_patt
        [[ $search_patt =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 3 to quit"; continue; }       
        if ((search_patt != 3))
        then
            search_pattern=$search_patt
            break
        elif ((search_patt == 3)); then
            show_available_search_options                    
        else
            echo -e "\nInvalid option, try again\n"
        fi
    done           
    local output_file=$(create_output_file) 
        var="$search_pattern" awk -F',' '$6 !~ ENVIRON["var"] {print $0}' tmpfile.csv | awk  ' #we are using environ in order to correctly grab the search pattern and use it in awk
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      
           
        }
        {
            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;        
            
                                   
        }
    ' > $output_file
    cat $output_file
    echo -e "\nYour search result has been save in $output_file\n"

    show_available_search_options
    else
        echo "You entered a wrong search option!"
    fi
}
#**********************END OF SEARCH BASED ON DESTINATION IP**********************#


#**********************START OF SEARCH BASED ON PROTOCOL**********************#
function search_single_file_by_protocol(){
    display_files    #Invoke the function that displays and allows user to select a file to perform a search on
    local output_file=$(create_output_file)    #Invoke the fucntion that creates the output file and save the result in a local variable
    
    grep $1 tmpfile.csv | awk  ' #run awk based on the protocol
    BEGIN{            
        FS=",";
        # OFS="\t";
        # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
        printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      
    }

    {        
         printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;      
    } 
    ' >  $output_file
    cat $output_file
   
    echo -e "\nYour search result has been saved in $output_file" 
}
#**********************END OF SEARCH BASED ON PROTOCOL**********************#


#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<END OF BASIC FUNCTINALITY>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#



#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<START OF ADVANCED FUNCTINALITY>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#


#The create_master_csv function merges all the available csv files that match the allowed criteria into one huge file
#This file is used in some of the advanced search operations
function create_master_csv(){
    master_file="master.csv" #Set the output file after merging all the relevant csv files
    for file in "${server_log_files[@]}" #loop through our csvs
    do
        if [[ "$file" != "$master_file" ]] #Avoid overwriting the file and thus preventing recursion
        then
            if [[ $i -eq 0 ]] #check if if it is the first file in the array
            then
                head -1 "$file" > "$master_file" #if true, copy the first file together with the header line for the fields and insert it into the output file to serve has header
            fi
            tail -n +2  "$file" >> "$master_file" #append each file to the first file starting from the second file 
            let i++ #Increment the counter until all the files have been appended to the master.csv file
        fi
    done   #terminate loop  
    echo $master_file #echo the file and capture it in the calling function as opposed to printing the result to the terminal. See line 333
}


function find_matches(){
    i=0 #counter
    if [[ $1 == "PROTOCOL" ]] #checking the search criteria selected
    then
        
        while :; do                        
            read -p  "PRTOTOCOL = " protocol #if it is protocol, prompt user to enter a protocol e.ICMP  
            [[ $protocol =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 9 to quit"; continue; }       
            if [[ $protocol =~ [A-Z]+$ ]]
            then
                protocol=$protocol
                break
            elif ((protocol == 9)); then
                show_available_search_options                    
            else
                echo -e "\nInvalid option, try again\n"
            fi
        done          
        echo -e "\n"
        local output_file=$(create_output_file)        
        grep "suspicious" $(create_master_csv) | var="$protocol" awk  -F',' '$3 ~ ENVIRON["var"] {print $0}' | awk ' #we are using environ in order to correctly grab the search pattern and use it in awk
        BEGIN{
            FS=",";
            # OFS="\t";     
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      

        }
        {            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                      
        }        
        END {print "There are " NR " matches";}      
            ' > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    elif [[ $1 == "SRC IP" ]]
    then        
        while :; do                        
        read -p "Enter search pattern e.g [EXT OR 1001]: " search_patt   
        [[ $search_patt =~ ^[A-Z0-9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [EXT, SER or 10004] OR enter q to quit"; continue; }       
        if [[ $search_patt != "q" ]]
        then
            search_patt=$search_patt
            break
        elif ((search_patt == "q")); then
            show_available_search_options                    
        else
            echo -e "\nInvalid option, try again\n"
        fi
    done 
        echo -e "\n"
        local output_file=$(create_output_file)        
        grep "suspicious" $(create_master_csv) | var="$search_patt" awk  -F',' '$4 ~ ENVIRON["var"] {print $0}' | awk ' #we are using environ in order to correctly grab the search pattern and use it in awk
        BEGIN{
            FS=",";
            # OFS="\t";     
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";                      

        }
        {            
             printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                      
        }        
        END {print "There are " NR " matches";}      
            ' > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    fi
}

function advanced_search_by_packets(){
    echo -e "\n1. PACKETS > (-gt)\n2. PACKETS < (-lt) \n3. PACKETS = (-eq) \n4. PACKETS != !(-eq)"
    read -p "Enter your option: " packet_opt      

    if [[ "$packet_opt" -eq 1 ]]
    then
        read -p "PACKETS > " num        
        local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 > var){ 
                sum+=$8;         
                printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;            
            }

           
        }
        END{
            print "There is a total of of " sum " packets that are greater than " var;
        }
            
        ' < tmpfile.csv > $output_file
        cat  $output_file
        echo -e "\nYour search result has been save in $output_file"
    elif [[ "$packet_opt" -eq 2 ]]
    then
        read -p "PACKETS < " num
        local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 < var){ 
                sum+=$8;        
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
                    
            }
            
        }
        END{
            print "There is a total of of " sum " packets that are less than " var;
        }
        ' < tmpfile.csv > $output_file   
    echo -e "\nYour search result has been save in $output_file"
    elif [[ "$packet_opt" -eq 3 ]]
    then
        read -p "PACKETS = " num
        local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
           if($8 = var){ 
                sum+=$8;         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }

           
        }
        END{
            print "There is a total of of " sum " packets that equals to " var;

        }
        ' < tmpfile.csv > $output_file   
        echo -e "\nYour search result has been save in $output_file"
    elif [[ "$packet_opt" -eq 4 ]]
    then
        read -p "PACKETS != " num
         local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($8 != var){    
                sum+=$8;        
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
                     
            }
            
        }
        END{
            print "There is a total of of " sum " packets that are not equal to " var;
        }
        ' < tmpfile.csv > $output_file
        echo -e "\nYour search result has been save in $output_file"
    else
        echo "Invalid option"
    fi          
}

function advanced_search_by_bytes(){
    echo -e "\n1. BYTES > (-gt)\n2. BYTES < (-lt) \n3. BYTES = (-eq) \n4. BYTES != !(-eq)"
    read -p "Enter your option: " byte_opt      

    if [[ "$byte_opt" -eq 1 ]]
    then
        read -p "BYTES > " num
        local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($9 > var){ 
                sum+=$9;         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }

           
        }
        END{
            print "There is a total of of " sum " bytes that are greater than " var;
        }
            
        ' < tmpfile.csv  > $output_file
        cat $output_file
       echo -e "\nYour search result has been save in $output_file"

    elif [[ "$byte_opt" -eq 2 ]]
    then
        read -p "BYTES < " num
        local output_file=$(create_output_file)        
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($9 < var){ 
                sum+=$9;        
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
                    
            }
            
        }
        END{
            print "There is a total of of " sum " bytes that are less than " var;
        }
        ' < tmpfile.csv  > $output_file
            cat $output_file
            echo -e "\nYour search result has been save in $output_file\n"

    elif [[ "$byte_opt" -eq 3 ]]
    then
        read -p "BYTES = " num   
        local output_file=$(create_output_file)       
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
           if($9 = var){ 
                sum+=$9;         
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;                
            }
           
        }
        END{
            print "There is a total of of " sum " bytes that equals to " var;

        }
        '< tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    elif [[ "$byte_opt" -eq 4 ]]
    then
        read -p "BYTES != " num
        local output_file=$(create_output_file)    
        awk -v var="$num" '
        BEGIN{
            FS=",";
            # OFS="\t";
            # print "PROTOCOL SRC IP\tSRC PORT DEST IP\tDEST PORT PACKETS\tBYTES";
            printf "%-12s %-12s %-12s %-12s %-12s %-12s %-6s \n", "PROTOCOL", "SRC IP", "SRC PORT", "DEST IP", "DEST PORT", "PACKETS", "BYTES";  
        }
        {
        
            if($9 != var){    
                sum+=$9;        
                 printf "%-10s %-15s %-10s %-15s %-12s %-10s %-10s \n", $3, $4, $5, $6, $7, $8, $9;          
                     
            }
            
        }
        END{
            print "There is a total of of " sum " bytes that are not equal to " var;
        }
        ' < tmpfile.csv > $output_file
        cat $output_file
        echo -e "\nYour search result has been save in $output_file\n"

    else
        echo "Invalid option"
    fi          
}


function advanced_search(){   
    i=1
    if [[ $1 -eq 1 ]]
    then              
        echo "You want to search based on ${criteria[$2]}"
        for criterion in "${criteria[@]}"
        do
            if [[ $criterion != "ADVANCED SEARCH" ]] #eliminate advanced search option from advanced search option
            then 
               echo -e "\t$i. $criterion"                          
            fi
            let i++           
        done  
        read -p "Choose one criteria above to search: " search_criterion
        
        echo "You are about to run an ${criteria[$2]} on all log files based on ${criteria[$search_criterion]}"
        find_matches "${criteria[$search_criterion]}"
    elif [[ $1 -eq 2 ]]
    then
        i=1        
         echo "You want to search based on ${criteria[$2]}"
        echo -e "\t1. Search based on packets\n"
        echo -e "\t2. Search based on bytes\n"
        # echo -e "\t3. Search based on packets and bytes\n"
        read -p "Enter option e.g [1 or 2]: " option_eq2
        if [[ $option_eq2 -eq 1 ]]
        then
            echo "You are about to run an ${criteria[$2]} on all log files based on packets"
            advanced_search_by_packets 
        elif [[ $option_eq2 -eq 2 ]]
        then
            echo "You are about to run an ${criteria[$2]} on all log files based on bytes"
            advanced_search_by_bytes
        else
            echo "Wrong option"
        fi        
    fi
}


#<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<END OF ADVANCED FUNCTINALITY>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>#


#The criteria_selector function iterates through the array that contains the Main Menu Items i.e criteria[] and checks which option the user has selected
#It then displays a submenu, which more specific,based on the main menu
 function criteria_selector(){
    for crit in "${criteria[@]}" #Looping through the main menu array
    do
        if [[ $1==$crit ]]  #check if the option the user selected actually exits in the main menu array
        then
            if [[ $1 -eq 9 ]] #if they selected 9, it means they want to exit the execution
            then
                exit  #terminate the execution and the entired application altogether
            fi


        #####additions for advanced fuctionality######
            if [[ $1 -eq 8 ]] #if they entered 8, they intend to perform advanced search operations
            then            
                while :; do
                    #Display a submenu
                    echo -e "\t1. Run searches on all available server access logs based on one (1) field\n"
                    echo -e "\t2. Get the sum of  PACKETS and/or BYTES fields and display them as final row\n"
                    echo -e "\t3. MAIN MENU\n"
                    #End of dispaly of a submenu
                    read -p "Enter option e.g [1 or 2 or 3]: " search_choice #ask for input
                    [[ $search_choice =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; } #check if the input is correct i.e it is numeric
                    if ((search_choice >= 1 && search_choice <= 2)); then  #If the input is okay, check if it lies within the searchable menu i.e 1 and 2          
                        advanced_search $search_choice $1 #if so, call the advanced_search function and pass it the search option fromthe submenu and the option that was passed in from the main menu($1)
                        break #break out of the loop
                    elif ((search_choice == 3)); then #if the users entered a number but is equl to 3, then they want to move away form the current view
                        show_available_search_options          #take them back to the main menu      
                    else
                        echo -e "\nInvalid option, try again\n" #Otherwise contniue asking for correct input
                    fi
                done           
            fi
        #end of additions for advanced fuctionality

        #Start of basic functionality submenus
            if [[ $1 -eq 6 || $1 -eq 7 ]]
            then
                if [[ $1 -eq 6 ]]           
                then
                    while :; do
                        echo -e "\n\t1. PACKETS > (-gt)\n\t2. PACKETS < (-lt) \n\t3. PACKETS = (-eq) \n\t4. PACKETS != !(-eq)\n\t5. MAIN MENU\n"
                        read -p "Enter your option: " packet_opt
                        [[ $packet_opt =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((packet_opt >= 1 && packet_opt <= 4)); then
                            display_files 
                            search_by_packet $packet_opt  
                            break
                        elif ((packet_opt == 5)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                    done                                
                fi
                if [[ $1 -eq 7 ]]
                then
                     while :; do
                        echo -e "\n\t1. BYTES > (-gt)\n\t2. BYTES < (-lt) \n\t3. BYTES = (-eq) \n\t4. BYTES != !(-eq)\n\t5. MAIN MENU\n"                        
                        read -p "Enter your option: " byte_opt
                        [[ $byte_opt =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((byte_opt >= 1 && byte_opt <= 4)); then
                            display_files 
                            bytes $byte_opt  
                            break
                        elif ((byte_opt == 5)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                    done                    
                fi        
            fi  

            if [[ $1 -eq 3 ]]
            then
                 while :; do
                        echo -e "\n\t1. SOURCE PORT > (-gt)\n\t2. SOURCE PORT < (-lt) \n\t3. SOURCE PORT = (-eq) \n\t4. SOURCE PORT != !(-eq)\n\t5. MAIN MENU\n"                        
                        read -p "Enter your option: " port_opt
                        [[ $port_opt =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((port_opt >= 1 && port_opt <= 4)); then
                            display_files 
                            search_by_source_port $port_opt  
                            break
                        elif ((port_opt == 5)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                done            
                
            fi


            if [[ $1 -eq 5 ]]
            then
                 while :; do
                        echo -e "\n\t1. DESTINATION PORT > (-gt)\n\t2. DESTINATION PORT < (-lt) \n\t3. DESTINATION PORT = (-eq) \n\t4. DESTINATION PORT != !(-eq)\n\t5. MAIN MENU\n"                        
                        read -p "Enter your option: " port_opt
                        [[ $port_opt =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((port_opt >= 1 && port_opt <= 4)); then
                            display_files 
                            search_by_dest_port $port_opt  
                            break
                        elif ((port_opt == 5)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                done            
                
            fi

            if [[ $1 -eq 2 || $1 -eq 4 ]]
            then
                if [[ $1 -eq 2 ]] 
                then
                    while :; do
                        echo -e "\n\t1. Search all logs that MATCH a source ip pattern" 
                        echo -e "\t2. Search all all logs that DON'T match a source ip pattern" 
                        echo -e "\t3. MAIN MENU\n"
                        read -p "Enter option: " search_option
                        [[ $search_option =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((search_option>= 1 && search_option<= 2)); then
                            display_files 
                            source_ip $search_option 
                            break
                        elif ((search_option == 3)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                    done                    
                    break
                else
                    while :; do
                        echo -e "\n\t1. Search all logs that MATCH a destination ip pattern" 
                        echo -e "\t2. Search all all logs that DON'T match a destination ip pattern"  
                        echo -e "\t3. MAIN MENU\n"
                        read -p "Enter option: " search_option
                        [[ $search_option =~ ^[0-9]+$ ]] || { echo "Enter a valid option"; continue; }
                        if ((search_option>= 1 && search_option<= 2)); then
                            display_files 
                            dest_ip $search_option 
                            break
                        elif ((search_option == 3)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                    done                    
                    break
                fi
            fi    
            if [[ $1 -eq 1 ]] 
            then
                while :; do                                              
                        read -p "${criteria[$1]} = " protocol
                        [[ $protocol =~ ^[A-Z9]+$ ]] || { echo "A valid option should be a string in uppercase e.g [UDP, ICMP, TCP or GRE] OR enter 9 to quit"; continue; }       
                        if ((protocol != 9))
                        then
                            search_single_file_by_protocol $protocol
                            show_available_search_options 
                            break
                        elif ((protocol == 9)); then
                            show_available_search_options                    
                        else
                            echo -e "\nInvalid option, try again\n"
                        fi
                    done           
            fi  
        fi 
     #End of basic functionality submenus
            
    done 
}

#This is the entry point to the core functionalities of the entire application
#The function simply displays the available such options and allows the user to quit the program incase they do not intend to do any searches
function show_available_search_options(){
    echo -e "\nAvailable search options: \n"
    for ((i = 1 ; i <= 9 ; i++))
        do
        echo -e "\t$i." "${criteria[$i]}"      #display the main menu   
    done

    echo -e "\n"           

    while :; do
        read -p "Enter the search criteria e.g [1, 2, 3, 4, 5, 6, 7, 8, 9]: " criterion #allow the user to select their choice of search 
        validate_option $criterion 1 9 #validate the options by invoking and passing the validate option function two args. The min and max options expected
        validate_option $1 || { echo "Enter a valid number"; continue; } #if the return value from the validate option is true then contunie with execution
        if ((criterion >= 1 && criterion <= 9)); then #check if the option entered lies within range allowed
            criteria_selector $criterion #if so, call the criteria_selectior function with the option the user has selected.
            break #break out of the loop
        else
            echo -e "Invalid menu option, try again" #incase the option is not valid ask the user to try again
            echo -e "\nAvailable search options: \n"
            for ((i = 1 ; i <= 9 ; i++))
                do
                echo -e "\t$i." "${criteria[$i]}"       #print all the avalable options once more... until the right choice is entered   
            done
            echo -e "\n"
            echo -e "Option out of range, try again\n"

        fi
    done
}

show_available_search_options #invoking the main menu function. This is the function that will run first when the script is executed