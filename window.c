#include "sniffer.h"

#define MAX_PACKETS 1000

int main(int argc, char *argv[]) {

  char filter_exp[50] = {0}, device[10] = {0}, packet_num_str[5] = {0},
    file_name[30] = {0};
  int packet_num = 0;

  initscr();

  /* Primary window */
  WINDOW *info_win = newwin(21, 80, 0, 0);
  refresh();
  wrefresh(info_win);

  /* Device window */
  WINDOW *dev_win = newwin(3, 20, 21, 0);
  refresh();
  mvwprintw(dev_win, 1, 1, "Device: ");
  wrefresh(dev_win);
  mvwscanw(dev_win, 2, 1, "%s", device);

  /* Default device */
  if(!device[0]) {
    mvwprintw(dev_win, 2, 1, "default");
    wrefresh(dev_win);
  }

  /* Filter expression window */
  WINDOW *filter_win = newwin(3, 20, 21, 20);
  refresh();
  mvwprintw(filter_win, 1, 1, "Filter: ");
  wrefresh(filter_win);
  mvwscanw(filter_win, 2, 1, "%s", filter_exp);

  /* Default filter */
  if(!filter_exp[0]) {
    strcpy(filter_exp, "ip");
  }
  mvwprintw(filter_win, 2, 1, "%s", filter_exp);
  wrefresh(filter_win);

  /* Packets to capture number window */
  WINDOW *packets_win = newwin(3, 20, 21, 40);
  refresh();
  mvwprintw(packets_win, 1, 1, "Packet num: ");
  wrefresh(packets_win);
  mvwscanw(packets_win, 2, 1, "%s", packet_num_str);
  packet_num = atoi(packet_num_str);

  /* Process invalid input */
  if (packet_num > MAX_PACKETS) {
    packet_num = MAX_PACKETS;
  }
  wclear(packets_win);
  mvwprintw(packets_win, 1, 1, "Packet num:");
  mvwprintw(packets_win, 2, 1, "%d", packet_num);
  wrefresh(packets_win);

  /* File window */
  WINDOW *file_win = newwin(3, 20, 21, 60);
  refresh();
  mvwprintw(file_win, 1, 1, "File: ");
  wrefresh(file_win);
  mvwscanw(file_win, 2, 1, "%s", file_name);

  curs_set(0);

  FILE *f = fopen(file_name, "w");
  if (f == NULL || !file_name[0]) {
     wprintw(info_win, "Error opening file. Press any button to exit...");
     wrefresh(info_win);
     getch();
     return 0;
  }

  if (packet_num > 0) {
    wprintw(info_win, "Started capturing...\n");
    wrefresh(info_win);
    sniffer(info_win, f, filter_exp, device, packet_num);
  } else {
    wprintw(info_win, "Invalid packets number. Press any button to exit...");
    wrefresh(info_win);
  }

  fclose(f);

  getch();
  endwin();

  return 0;
}
