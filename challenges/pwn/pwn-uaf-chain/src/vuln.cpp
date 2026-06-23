#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

class Animal {
public:
    char name[32];
    virtual void speak() = 0;
    virtual void info()  = 0;
    virtual ~Animal() {}
};

class Dog : public Animal {
public:
    Dog(const char *n) { strncpy(name, n, 31); name[31] = '\0'; }
    void speak() override { printf("%s says: Woof!\n", name); }
    void info()  override { printf("Dog object at: %p\n", (void*)this); }
    ~Dog() override {}
};

class Cat : public Animal {
public:
    Cat(const char *n) { strncpy(name, n, 31); name[31] = '\0'; }
    void speak() override { printf("%s says: Meow!\n", name); }
    void info()  override { printf("Cat object at: %p\n", (void*)this); }
    ~Cat() override {}
};

/* Win function — called when vtable is hijacked */
extern "C" void give_flag() {
    system("cat /home/ctf/flag.txt");
}

#define MAX_ANIMALS 8
Animal *shelter[MAX_ANIMALS];

void setup() {
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void print_menu() {
    puts("\n=== Animal Shelter ===");
    puts("1. Add Dog");
    puts("2. Add Cat");
    puts("3. Make speak");
    puts("4. Show info (leak address)");
    puts("5. Remove animal");
    puts("6. Fill slot (any data)");
    puts("7. Exit");
    printf("> ");
}

int get_slot() {
    int s;
    printf("Slot [0-%d]: ", MAX_ANIMALS-1);
    scanf("%d", &s);
    getchar();
    return s;
}

int main() {
    setup();
    puts("Welcome to the Animal Shelter!");
    printf("[debug] give_flag=%p\n", (void*)give_flag);

    while (1) {
        print_menu();
        int choice;
        if (scanf("%d", &choice) != 1) break;
        getchar();

        int s;
        char name_buf[32];

        switch (choice) {
            case 1: /* Add Dog */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS) { puts("Invalid slot"); break; }
                printf("Name: ");
                fgets(name_buf, sizeof(name_buf), stdin);
                name_buf[strcspn(name_buf, "\n")] = '\0';
                shelter[s] = new Dog(name_buf);
                printf("Dog added at slot %d\n", s);
                break;

            case 2: /* Add Cat */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS) { puts("Invalid slot"); break; }
                printf("Name: ");
                fgets(name_buf, sizeof(name_buf), stdin);
                name_buf[strcspn(name_buf, "\n")] = '\0';
                shelter[s] = new Cat(name_buf);
                printf("Cat added at slot %d\n", s);
                break;

            case 3: /* Make speak — UAF if freed */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS || shelter[s] == nullptr) {
                    puts("Empty slot");
                    break;
                }
                /* BUG: no check if pointer is freed — UAF call through vtable */
                shelter[s]->speak();
                break;

            case 4: /* Show info — useful for address leak */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS || shelter[s] == nullptr) {
                    puts("Empty slot");
                    break;
                }
                shelter[s]->info();
                break;

            case 5: /* Remove — BUG: doesn't null the pointer */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS || shelter[s] == nullptr) {
                    puts("Empty slot");
                    break;
                }
                delete shelter[s];
                /* BUG: shelter[s] not set to nullptr -> UAF */
                puts("Removed!");
                break;

            case 6: /* Fill slot with raw data — reclaim freed chunk */
                s = get_slot();
                if (s < 0 || s >= MAX_ANIMALS) { puts("Invalid slot"); break; }
                {
                    /* Allocate same-size chunk (sizeof Dog/Cat ~ 48 bytes) */
                    char *raw = (char*)malloc(48);
                    printf("Data (48 bytes): ");
                    read(STDIN_FILENO, raw, 48);
                    /* Store raw pointer — when speak() is called, it uses this as vtable */
                    shelter[s] = (Animal*)raw;
                    printf("Raw data placed at slot %d: %p\n", s, (void*)raw);
                }
                break;

            case 7:
                exit(0);
        }
    }
    return 0;
}
