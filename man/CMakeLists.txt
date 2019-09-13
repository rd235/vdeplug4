cmake_minimum_required(VERSION 3.13)

file(GLOB MAN1_PAGES ${PROJECT_SOURCE_DIR}/man/*.1)
install(FILES ${MAN1_PAGES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_open.3
)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_close.3
)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_recv.3
)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_send.3
)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_datafd.3
)

install(
        FILES libvdeplug.3
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man3
        RENAME vde_stlfd.3
)
